@@
identifier func =~ ".*_create$";
identifier event, dnode, resource;
@@

int
- func(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
+ func(struct nb_cb_create_args *args)
  {
<...
(
- event
+ args->event
|
- dnode
+ args->dnode
|
- resource
+ args->resource
)
...>
  }

@@
identifier func =~ ".*_modify$";
identifier event, dnode, resource;
@@

int
- func(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
+ func(struct nb_cb_modify_args *args)
  {
<...
(
- event
+ args->event
|
- dnode
+ args->dnode
|
- resource
+ args->resource
)
...>
  }

@@
identifier func =~ ".*_destroy$";
identifier event, dnode;
@@

int
- func(enum nb_event event, const struct lyd_node *dnode)
+ func(struct nb_cb_destroy_args *args)
  {
<...
(
- dnode
+ args->dnode
|
- event
+ args->event
)
...>
  }

@@
identifier func =~ ".*_pre_validate$";
identifier dnode;
@@

int
- func(const struct lyd_node dnode)
+ func(struct nb_cb_pre_validate_args *args)
  {
<...
- dnode
+ args->dnode
...>
  }

@@
identifier func =~ ".*_apply_finish$";
identifier dnode;
@@

void
- func(const struct lyd_node *dnode)
+ func(struct nb_cb_apply_finish_args *args)
  {
<...
- dnode
+ args->dnode
...>
  }

@@
identifier func =~ ".*_get_elem$";
identifier xpath, list_entry;
@@

struct yang_data *
- func(const char *xpath, const void *list_entry)
+ func(struct nb_cb_get_elem_args *args)
  {
<...
(
- xpath
+ args->xpath
|
- list_entry
+ args->list_entry
)
...>
  }

@@
identifier func =~ ".*_get_next$";
identifier parent_list_entry, list_entry;
@@

const void *
- func(const void *parent_list_entry, const void *list_entry)
+ func(struct nb_cb_get_next_args *args)
  {
<...
(
- parent_list_entry
+ args->parent_list_entry
|
- list_entry
+ args->list_entry
)
...>
  }

@@
identifier func =~ ".*_get_keys$";
identifier list_entry, keys;
@@

int
- func(const void *list_entry, struct yang_list_keys *keys)
+ func(struct nb_cb_get_keys_args *args)
  {
<...
(
- list_entry
+ args->list_entry
|
- keys
+ args->keys
)
...>
  }

@@
identifier func =~ ".*_lookup_entry$";
identifier parent_list_entry, keys;
@@

const void *
- func(const void *parent_list_entry, const struct yang_list_keys *keys)
+ func(struct nb_cb_lookup_entry_args *args)
  {
<...
(
- parent_list_entry
+ args->parent_list_entry
|
- keys
+ args->keys
)
...>
  }

@@
identifier func =~ ".*_rpc$";
identifier xpath, input, output;
@@

int
- func(const char *xpath, const struct list *input, struct list *output)
+ func(struct nb_cb_rpc_args *args)
  {
<...
(
- xpath
+ args->xpath
|
- input
+ args->input
|
- output
+ args->output
)
...>
  }

@@
identifier func =~ ".*_create$";
identifier event, dnode, resource;
@@

int
- func(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
+ func(struct nb_cb_create_args *args)
;

@@
identifier func =~ ".*_modify$";
identifier event, dnode, resource;
@@

int
- func(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
+ func(struct nb_cb_modify_args *args)
;

@@
identifier func =~ ".*_destroy$";
identifier event, dnode;
@@

int
- func(enum nb_event event, const struct lyd_node *dnode)
+ func(struct nb_cb_destroy_args *args)
;

@@
identifier func =~ ".*_pre_validate$";
identifier dnode;
@@

int
- func(const struct lyd_node dnode)
+ func(struct nb_cb_pre_validate_args *args)
;

@@
identifier func =~ ".*_apply_finish$";
identifier dnode;
@@

void
- func(const struct lyd_node *dnode)
+ func(struct nb_cb_apply_finish_args *args)
;

@@
identifier func =~ ".*_get_elem$";
identifier xpath, list_entry;
@@

struct yang_data *
- func(const char *xpath, const void *list_entry)
+ func(struct nb_cb_get_elem_args *args)
;

@@
identifier func =~ ".*_get_next$";
identifier parent_list_entry, list_entry;
@@

const void *
- func(const void *parent_list_entry, const void *list_entry)
+ func(struct nb_cb_get_next_args *args)
;

@@
identifier func =~ ".*_get_keys$";
identifier list_entry, keys;
@@

int
- func(const void *list_entry, struct yang_list_keys *keys)
+ func(struct nb_cb_get_keys_args *args)
;

@@
identifier func =~ ".*_lookup_entry$";
identifier parent_list_entry, keys;
@@

const void *
- func(const void *parent_list_entry, const struct yang_list_keys *keys)
+ func(struct nb_cb_lookup_entry_args *args)
;

@@
identifier func =~ ".*_rpc$";
identifier xpath, input, output;
@@

int
- func(const char *xpath, const struct list *input, struct list *output)
+ func(struct nb_cb_rpc_args *args)
;
