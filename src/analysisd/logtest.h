/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "../headers/pthreads_op.h"
#include "../headers/list_op.h"
#include "../headers/defs.h"
#include "../os_net/os_net.h"
#include "rules.h"
#include "decoders/decoder.h"
#include "lists.h"
#include "eventinfo.h"

typedef struct sessionLogtest {

    int token;

    RuleNode *rulelist;
    OSDecoderNode *decoderlist_forpname;
    OSDecoderNode *decoderlist_nopname;
    ListNode *cdblistnode;
    ListRule *cdblistrule;
    EventList *eventlist;

} sessionLogtest;

OSList *all_sessions;

pthread_mutex_t logtest_mutex;

/**
 * @brief Initialize Wazuh Logtest. Initialize the listener and creat threads.
 * Then, call function wazuh_logtest_init.
 */
void wazuh_logtest_init();

/**
 * @brief Main function of Wazuh Logtest module. Listen and treat conexions with clients.
 * @param connection The listener where clients connect
 */
void wazuh_logtest_main(int *connection);

/**
 * @brief Create resources necessaries to service client
 * @param fd File descriptor which represents the client
 */
void w_initialize_session(int token);

/**
 * @brief Process client's request
 * @param fd File descriptor which represents the client
 */
void w_process_log(int token);

/**
 * @brief Free resources after client close connection
 * @param fd File descriptor which represents the client
 */
void w_remove_session(int token);

/**
 * @brief Check all sessions. If session is created and the client has been offline
 * for more than 15 minutes, remove it.
 */
void w_check_active_sessions();
