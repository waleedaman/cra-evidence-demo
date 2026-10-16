/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Connected sensor node for the CRA evidence demo.
 *
 * Reads a simulated temperature sensor and publishes the value over MQTT
 * with TLS (Zephyr MQTT library + TLS sockets backed by Mbed TLS). The payload
 * is built with the vendored cJSON library (lib/cjson). The broker
 * certificate is verified against a demo CA that is embedded at build time.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/socket_poll.h>
#include <zephyr/net/tls_credentials.h>

#include <app_version.h>

#include "cJSON.h"
#include "sensor_sim.h"

LOG_MODULE_REGISTER(sensor_node, LOG_LEVEL_INF);

#define CA_CERT_TAG 1
#define CONNECT_TIMEOUT_MS 5000
#define CONNECT_TRIES 5
#define TOPIC "cra-demo/" CONFIG_APP_DEVICE_ID "/temperature"

static const unsigned char demo_ca_der[] = {
#include "demo_ca.der.inc"
};

static const sec_tag_t sec_tags[] = {CA_CERT_TAG};

static uint8_t rx_buffer[256];
static uint8_t tx_buffer[256];
static struct mqtt_client client;
static struct net_sockaddr_storage broker;
static struct zsock_pollfd fds[1];
static bool connected;

static void mqtt_evt_handler(struct mqtt_client *const c, const struct mqtt_evt *evt)
{
	ARG_UNUSED(c);

	switch (evt->type) {
	case MQTT_EVT_CONNACK:
		if (evt->result == 0) {
			connected = true;
			LOG_INF("MQTT connected (TLS) to %s:%d", CONFIG_APP_MQTT_BROKER_HOST,
				CONFIG_APP_MQTT_BROKER_PORT);
		} else {
			LOG_ERR("MQTT connect refused: %d", evt->result);
		}
		break;
	case MQTT_EVT_DISCONNECT:
		connected = false;
		LOG_INF("MQTT disconnected (%d)", evt->result);
		break;
	default:
		break;
	}
}

static int resolve_broker(void)
{
	if (strlen(CONFIG_APP_MQTT_BROKER_ADDR) > 0) {
		struct net_sockaddr_in *b4 = (struct net_sockaddr_in *)&broker;

		b4->sin_family = NET_AF_INET;
		b4->sin_port = net_htons(CONFIG_APP_MQTT_BROKER_PORT);
		if (zsock_inet_pton(NET_AF_INET, CONFIG_APP_MQTT_BROKER_ADDR, &b4->sin_addr) != 1) {
			LOG_ERR("Invalid broker address %s", CONFIG_APP_MQTT_BROKER_ADDR);
			return -EINVAL;
		}
		return 0;
	}

	struct zsock_addrinfo hints = {
		.ai_family = NET_AF_INET,
		.ai_socktype = NET_SOCK_STREAM,
	};
	struct zsock_addrinfo *res = NULL;
	char port[8];
	int ret;

	snprintf(port, sizeof(port), "%d", CONFIG_APP_MQTT_BROKER_PORT);
	ret = zsock_getaddrinfo(CONFIG_APP_MQTT_BROKER_HOST, port, &hints, &res);
	if (ret != 0 || res == NULL) {
		LOG_ERR("Cannot resolve %s (%d)", CONFIG_APP_MQTT_BROKER_HOST, ret);
		return -EHOSTUNREACH;
	}
	memcpy(&broker, res->ai_addr, MIN(res->ai_addrlen, sizeof(broker)));
	zsock_freeaddrinfo(res);
	return 0;
}

static void client_setup(void)
{
	struct mqtt_sec_config *tls;

	mqtt_client_init(&client);
	client.broker = &broker;
	client.evt_cb = mqtt_evt_handler;
	client.client_id.utf8 = (const uint8_t *)CONFIG_APP_DEVICE_ID;
	client.client_id.size = strlen(CONFIG_APP_DEVICE_ID);
	client.protocol_version = MQTT_VERSION_3_1_1;
	client.rx_buf = rx_buffer;
	client.rx_buf_size = sizeof(rx_buffer);
	client.tx_buf = tx_buffer;
	client.tx_buf_size = sizeof(tx_buffer);

	client.transport.type = MQTT_TRANSPORT_SECURE;
	tls = &client.transport.tls.config;
	tls->peer_verify = ZSOCK_TLS_PEER_VERIFY_REQUIRED;
	tls->cipher_list = NULL;
	tls->sec_tag_list = sec_tags;
	tls->sec_tag_count = ARRAY_SIZE(sec_tags);
	tls->hostname = CONFIG_APP_MQTT_BROKER_HOST;
}

static int wait_input(int timeout_ms)
{
	int ret;

	fds[0].fd = client.transport.tls.sock;
	fds[0].events = ZSOCK_POLLIN;
	ret = zsock_poll(fds, 1, timeout_ms);
	if (ret > 0) {
		return mqtt_input(&client);
	}
	return ret;
}

static int connect_broker(void)
{
	for (int attempt = 1; attempt <= CONNECT_TRIES; attempt++) {
		int ret;

		client_setup();
		ret = mqtt_connect(&client);
		if (ret != 0) {
			LOG_WRN("Connect attempt %d failed (%d)", attempt, ret);
			k_sleep(K_SECONDS(1));
			continue;
		}
		(void)wait_input(CONNECT_TIMEOUT_MS);
		if (connected) {
			return 0;
		}
		mqtt_abort(&client);
	}
	return -ECONNREFUSED;
}

static int publish_reading(uint32_t seq)
{
	struct mqtt_publish_param param = {0};
	char payload[128];
	cJSON *msg = cJSON_CreateObject();
	bool ok;

	/* Integers only: the board's C library is built without float printf. */
	ok = msg != NULL &&
	     cJSON_AddStringToObject(msg, "device", CONFIG_APP_DEVICE_ID) != NULL &&
	     cJSON_AddStringToObject(msg, "fw", APP_VERSION_STRING) != NULL &&
	     cJSON_AddNumberToObject(msg, "seq", (double)seq) != NULL &&
	     cJSON_AddNumberToObject(msg, "temp_mc", (double)sensor_sim_read_mdegc(seq)) != NULL &&
	     cJSON_PrintPreallocated(msg, payload, sizeof(payload), false);
	cJSON_Delete(msg);
	if (!ok) {
		LOG_ERR("Cannot build payload");
		return -ENOMEM;
	}

	param.message.topic.topic.utf8 = (const uint8_t *)TOPIC;
	param.message.topic.topic.size = strlen(TOPIC);
	param.message.topic.qos = MQTT_QOS_0_AT_MOST_ONCE;
	param.message.payload.data = payload;
	param.message.payload.len = strlen(payload);
	param.message_id = (uint16_t)(seq + 1);

	LOG_INF("publish %s %s", TOPIC, payload);
	return mqtt_publish(&client, &param);
}

int main(void)
{
	int ret;

	LOG_INF("sensor node %s (%s) on %s", APP_VERSION_STRING, CONFIG_APP_DEVICE_ID,
		CONFIG_BOARD_TARGET);

	ret = tls_credential_add(CA_CERT_TAG, TLS_CREDENTIAL_CA_CERTIFICATE, demo_ca_der,
				 sizeof(demo_ca_der));
	if (ret < 0) {
		LOG_ERR("Cannot register CA certificate (%d)", ret);
		return 0;
	}

	ret = resolve_broker();
	if (ret == 0) {
		ret = connect_broker();
	}
	if (ret != 0) {
		LOG_ERR("No broker connection (%d)", ret);
		return 0;
	}

	for (uint32_t seq = 0;
	     CONFIG_APP_PUBLISH_COUNT == 0 || seq < CONFIG_APP_PUBLISH_COUNT; seq++) {
		ret = publish_reading(seq);
		if (ret != 0) {
			LOG_ERR("Publish failed (%d)", ret);
			break;
		}
		(void)wait_input(CONFIG_APP_PUBLISH_INTERVAL_MS);
		(void)mqtt_live(&client);
		if (!connected) {
			break;
		}
	}

	(void)mqtt_disconnect(&client, NULL);
	LOG_INF("done");
	return 0;
}
