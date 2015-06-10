/**
 * collectd - src/write_mongodb.c
 * Copyright (C) 2010-2013  Florian Forster
 * Copyright (C) 2010       Akkarit Sangpetch
 * Copyright (C) 2012       Chris Lundquist
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *   Florian Forster <octo at collectd.org>
 *   Akkarit Sangpetch <asangpet at andrew.cmu.edu>
 *   Chris Lundquist <clundquist at bluebox.net>
 **/

#include "collectd.h"
#include "plugin.h"
#include "common.h"
#include "configfile.h"
#include "utils_cache.h"

#include <pthread.h>

#if HAVE_STDINT_H
# define MONGO_HAVE_STDINT 1
#else
# define MONGO_USE_LONG_LONG_INT 1
#endif
#include <mongoc.h>

// #if (MONGO_MAJOR == 0) && (MONGO_MINOR < 8)
// # define bson_alloc()    bson_create()
// # define bson_dealloc(b) bson_dispose(b)
// #endif


struct wm_node_s
{
  char name[DATA_MAX_NAME_LEN];

  char *host;
  int port;
  int timeout;

  /* Authentication information */
  char *db;
  char *user;
  char *passwd;

  _Bool store_rates;
  bool connected;

  mongoc_client_t *client;
  pthread_mutex_t lock;
};
typedef struct wm_node_s wm_node_t;

/*
 * Functions
 */
static bson_t *wm_create_bson (const data_set_t *ds, /* {{{ */
    const value_list_t *vl,
    _Bool store_rates)
{
  bson_t *ret;
  gauge_t *rates;
  int i;

  ret = bson_new(); /* matched by bson_free() */
  if (ret == NULL)
  {
    ERROR ("write_mongodb plugin: bson_create failed.");
    return (NULL);
  }

  if (store_rates)
  {
    rates = uc_get_rate (ds, vl);
    if (rates == NULL)
    {
      ERROR ("write_mongodb plugin: uc_get_rate() failed.");
      return (NULL);
    }
  }
  else
  {
    rates = NULL;
  }

  // bson_init (ret); /* matched by bson_destroy() */
  bson_append_date_time(ret, "time", sizeof(CDTIME_T_TO_MS (vl->time)), CDTIME_T_TO_MS (vl->time) );
  BSON_APPEND_UTF8(ret, "host", vl->host);
  BSON_APPEND_UTF8(ret, "plugin", vl->plugin);
  BSON_APPEND_UTF8(ret, "plugin_instance", vl->plugin_instance);
  BSON_APPEND_UTF8(ret, "type", vl->type);
  BSON_APPEND_UTF8(ret, "type_instance", vl->type_instance);

  bson_append_array_begin (ret, "values", -1, NULL); /* {{{ */
  for (i = 0; i < ds->ds_num; i++)
  {
    char key[16];

    ssnprintf (key, sizeof (key), "%i", i);

    if (ds->ds[i].type == DS_TYPE_GAUGE)
      BSON_APPEND_DOUBLE(ret, key, vl->values[i].gauge);
    else if (store_rates)
      BSON_APPEND_DOUBLE(ret, key, (double) rates[i]);
    else if (ds->ds[i].type == DS_TYPE_COUNTER)
      BSON_APPEND_INT64(ret, key,  vl->values[i].counter);
    else if (ds->ds[i].type == DS_TYPE_DERIVE)
      BSON_APPEND_INT64(ret, key, vl->values[i].derive);
    else if (ds->ds[i].type == DS_TYPE_ABSOLUTE)
      BSON_APPEND_INT64(ret, key, vl->values[i].absolute);
    else
      assert (23 == 42);
  }
  bson_append_array_end(ret, NULL); /* }}} values */

  bson_append_array_begin (ret, "dstypes", -1, NULL); /* {{{ */
  for (i = 0; i < ds->ds_num; i++)
  {
    char key[16];

    ssnprintf (key, sizeof (key), "%i", i);

    if (store_rates)
      BSON_APPEND_UTF8 (ret, key, "gauge");
    else
      BSON_APPEND_UTF8 (ret, key, DS_TYPE_TO_STRING (ds->ds[i].type) );
  }
  bson_append_array_end(ret, NULL); /* }}} dstypes */

  bson_append_array_begin (ret, "dsnames", -1, NULL); /* {{{ */
  for (i = 0; i < ds->ds_num; i++)
  {
    char key[16];

    ssnprintf (key, sizeof (key), "%i", i);
    BSON_APPEND_UTF8 (ret, key, ds->ds[i].name);
  }
  bson_append_array_end (ret, NULL); /* }}} dsnames */

  bson_append_document_end (ret, NULL);

  sfree (rates);
  return (ret);
} /* }}} bson *wm_create_bson */

static int wm_initialize(wm_node_t *node) {
  if (!node->connected)
  {
    INFO ("write_mongodb plugin: Connecting to [%s]:%i",
        (node->host != NULL) ? node->host : "localhost",
        (node->port != 0) ? node->port : MONGOC_DEFAULT_PORT);
    //status = mongoc_connect (node->client, node->host, node->port);
    // TODO
    node->client = mongoc_client_new ("mongodb://localhost:27017");
    if (node->client) {
      ERROR ("write_mongodb plugin: Connecting to [%s]:%i failed.",
          (node->host != NULL) ? node->host : "localhost",
          (node->port != 0) ? node->port : MONGOC_DEFAULT_PORT);
      mongoc_client_destroy (node->client);
      node->connected = 0;
      pthread_mutex_unlock (&node->lock);
      return (-1);
    }

    if ((node->db != NULL) && (node->user != NULL) && (node->passwd != NULL))
    {
      // status = mongo_cmd_authenticate (node->client, node->db, node->user, node->passwd);
      // TODO
      node->client = mongoc_client_new ("mongodb://localhost:27017");
      if (node->client)
      {
        ERROR ("write_mongodb plugin: Authenticating to [%s]%i for database "
            "\"%s\" as user \"%s\" failed.",
          (node->host != NULL) ? node->host : "localhost",
          (node->port != 0) ? node->port : MONGOC_DEFAULT_PORT,
          node->db, node->user);
        mongoc_client_destroy (node->client);
        node->connected = 0;
        pthread_mutex_unlock (&node->lock);
        return (-1);
      }
    }
    /*
    if (node->timeout > 0) {
      status = mongo_set_op_timeout (node->client, node->timeout);
      if (status) {
        WARNING ("write_mongodb plugin: mongo_set_op_timeout(%i) failed: %s",
            node->timeout, node->client->errstr);
      }
    }
    */
  }
  node->connected = 1;
  return 0;
}

static int wm_write (const data_set_t *ds, /* {{{ */
    const value_list_t *vl,
    user_data_t *ud)
{
  wm_node_t *node = ud->data;
  mongoc_collection_t *collection;
  bson_t *bson_record;
  bson_error_t error;
  int status;

  bson_record = wm_create_bson (ds, vl, node->store_rates);
  if (bson_record == NULL)
    return (ENOMEM);

  pthread_mutex_lock (&node->lock);
  wm_initialize(node);

  collection = mongoc_client_get_collection (node->client, "collectd", vl->plugin);
  status = mongoc_collection_insert (collection, MONGOC_INSERT_NONE, bson_record, NULL, &error);

  if (status)
  {
    ERROR ( "write_mongodb plugin: error inserting record: %s", error.message);
    mongoc_client_destroy (node->client);
    node->connected = 0;
  }

  pthread_mutex_unlock (&node->lock);

  /* free our resource as not to leak memory */
  // bson_destroy (bson_record); /* matches bson_init() */
  bson_free (bson_record); /* matches bson_new() */

  return (0);
} /* }}} int wm_write */

static void wm_config_free (void *ptr) /* {{{ */
{
  wm_node_t *node = ptr;

  if (node == NULL)
    return;

  mongoc_client_destroy (node->client);
  node->connected = 0;

  sfree (node->host);
  sfree (node);
} /* }}} void wm_config_free */

static int wm_config_node (oconfig_item_t *ci) /* {{{ */
{
  wm_node_t *node;
  int status;
  int i;

  node = malloc (sizeof (*node));
  if (node == NULL)
    return (ENOMEM);
  memset (node, 0, sizeof (*node));
  mongoc_init ();
  node->host = NULL;
  node->store_rates = 1;
  pthread_mutex_init (&node->lock, /* attr = */ NULL);

  status = cf_util_get_string_buffer (ci, node->name, sizeof (node->name));

  if (status != 0)
  {
    sfree (node);
    return (status);
  }

  for (i = 0; i < ci->children_num; i++)
  {
    oconfig_item_t *child = ci->children + i;

    if (strcasecmp ("Host", child->key) == 0)
      status = cf_util_get_string (child, &node->host);
    else if (strcasecmp ("Port", child->key) == 0)
    {
      status = cf_util_get_port_number (child);
      if (status > 0)
      {
        node->port = status;
        status = 0;
      }
    }
    else if (strcasecmp ("Timeout", child->key) == 0)
      status = cf_util_get_int (child, &node->timeout);
    else if (strcasecmp ("StoreRates", child->key) == 0)
      status = cf_util_get_boolean (child, &node->store_rates);
    else if (strcasecmp ("Database", child->key) == 0)
      status = cf_util_get_string (child, &node->db);
    else if (strcasecmp ("User", child->key) == 0)
      status = cf_util_get_string (child, &node->user);
    else if (strcasecmp ("Password", child->key) == 0)
      status = cf_util_get_string (child, &node->passwd);
    else
      WARNING ("write_mongodb plugin: Ignoring unknown config option \"%s\".",
          child->key);

    if (status != 0)
      break;
  } /* for (i = 0; i < ci->children_num; i++) */

  if ((node->db != NULL) || (node->user != NULL) || (node->passwd != NULL))
  {
    if ((node->db == NULL) || (node->user == NULL) || (node->passwd == NULL))
    {
      WARNING ("write_mongodb plugin: Authentication requires the "
          "\"Database\", \"User\" and \"Password\" options to be specified, "
          "but at last one of them is missing. Authentication will NOT be "
          "used.");
      sfree (node->db);
      sfree (node->user);
      sfree (node->passwd);
    }
  }

  if (status == 0)
  {
    char cb_name[DATA_MAX_NAME_LEN];
    user_data_t ud;

    ssnprintf (cb_name, sizeof (cb_name), "write_mongodb/%s", node->name);

    ud.data = node;
    ud.free_func = wm_config_free;

    status = plugin_register_write (cb_name, wm_write, &ud);
    INFO ("write_mongodb plugin: registered write plugin %s %d",cb_name,status);
  }

  if (status != 0)
    wm_config_free (node);

  return (status);
} /* }}} int wm_config_node */

static int wm_config (oconfig_item_t *ci) /* {{{ */
{
  int i;

  for (i = 0; i < ci->children_num; i++)
  {
    oconfig_item_t *child = ci->children + i;

    if (strcasecmp ("Node", child->key) == 0)
      wm_config_node (child);
    else
      WARNING ("write_mongodb plugin: Ignoring unknown "
          "configuration option \"%s\" at top level.", child->key);
  }

  return (0);
} /* }}} int wm_config */

void module_register (void)
{
  plugin_register_complex_config ("write_mongodb", wm_config);
}

/* vim: set sw=2 sts=2 tw=78 et fdm=marker : */
