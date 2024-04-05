/*
 * Copyright (c) 2024 Space Cubics, LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <csp/csp.h>

static void *setup(void)
{
	csp_init();
	return NULL;
}

ZTEST(buffer, test_buffer_count)
{
	csp_packet_t *packets[CSP_BUFFER_COUNT];
	int i;

	memset(packets, 0, sizeof(packets));

	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);

	for (i = 0; i < CSP_BUFFER_COUNT; i++) {
		packets[i] = csp_buffer_get(0);
		zassert_true(packets[i] != NULL, NULL);
	}

	zassert_true(csp_buffer_remaining() == 0);

	for (i = 0; i < CSP_BUFFER_COUNT; i++) {
		csp_buffer_free(packets[i]);
	}

	zassert_true(csp_buffer_remaining() == CSP_BUFFER_COUNT);
}

ZTEST(buffer, test_buffer_over_allocate)
{
	csp_packet_t *packets[CSP_BUFFER_COUNT];
	csp_packet_t *p;
	int i;

	memset(packets, 0, sizeof(packets));

	for (i = 0; i < CSP_BUFFER_COUNT; i++) {
		packets[i] = csp_buffer_get(0);
		zassert_true(packets[i] != NULL, NULL);
	}

	zassert_true(csp_buffer_remaining() == 0);
	p = csp_buffer_get(0);
	zassert_true(p == NULL, NULL);

	for (i = 0; i < CSP_BUFFER_COUNT; i++) {
		csp_buffer_free(packets[i]);
	}
}

ZTEST(buffer, test_buffer_clone_whithout_header)
{
	csp_packet_t *packet, *clone = NULL;
	int ret;

	packet = csp_buffer_get(0);
	zassert_true(packet != NULL, NULL);

	memcpy(packet->data, "Hello", 5);
	packet->length = 5;

	/* First try clone without header */
	clone = csp_buffer_clone(packet);
	zassert_not_null(clone, "Failed to clone CSP buffer");
	zassert_equal(packet->length, clone->length, "Packet and clone have different length");
	ret = strcmp(packet->data, clone->data);
	zassert_equal(ret, 0, "Packet and clone have different data");

	csp_buffer_free(packet);
	csp_buffer_free(clone);
}

ZTEST(buffer, test_buffer_clone_with_header)
{
	csp_packet_t *packet, *clone = NULL;
	int ret;

	packet = csp_buffer_get(0);
	zassert_true(packet != NULL, NULL);

	memcpy(packet->data, "Hello", 5);
	packet->length = 5;

	/* Try clone with header */
	csp_id_prepend(packet);
	clone = csp_buffer_clone(packet);
	zassert_not_null(clone, "Failed to clone CSP buffer");
	zassert_equal(packet->length, clone->length, "Packet and clone have different length");
	/* Should also test that packet->frame_begin are different pointer */
	/* zassert_not_equal(packet->frame_begin,clone->frame_begin, "Packet and clone have the same
	 * frame_begin"); */
	zassert_equal(packet->frame_length, clone->frame_length,
		      "Packet and clone have different frame_length");
	ret = strcmp(packet->data, clone->data);
	zassert_equal(ret, 0, "Packet and clone have different data");

	csp_buffer_free(packet);
	csp_buffer_free(clone);
}

ZTEST_SUITE(buffer, NULL, setup, NULL, NULL, NULL);
