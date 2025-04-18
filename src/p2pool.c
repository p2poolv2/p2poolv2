#include "p2pool.h"
#include "ckpool.h"
#include "libckpool.h"
#include "json.h"

bool get_p2pool_difficulty(connsock_t *cs, double *difficulty) {
    json_t *val = NULL, *res_val = NULL;
    char *response = NULL;
    bool ret = false;

    val = json_object();
    json_object_set_new(val, "method", json_string("get_network_difficulty"));
    json_object_set_new(val, "params", json_array());
    json_object_set_new(val, "id", json_integer(1));

    if (!send_json_msg(cs, val)) {
        LOGWARNING("Failed to send get_network_difficulty message");
        goto out;
    }

    if (!read_http_response(cs, &response)) {
        LOGWARNING("Failed to read get_network_difficulty response");
        goto out;
    }

    res_val = json_loads(response, 0, NULL);
    if (!res_val) {
        LOGWARNING("Failed to parse json response: %s", response);
        goto out;
    }

    json_t *result = json_object_get(res_val, "result");
    if (!result) {
        LOGWARNING("Failed to find result in response");
        goto out;
    }

    double diff = json_number_value(result);
    if (diff <= 0) {
        LOGWARNING("Invalid difficulty value: %f", diff);
        goto out;
    }

    *difficulty = diff;
    ret = true;

out:
    if (val)
        json_decref(val);
    if (res_val)
        json_decref(res_val);
    free(response);
    return ret;
} 