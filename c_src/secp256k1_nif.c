#include "erl_nif.h"
#include "secp256k1_recovery.h"

static ErlNifResourceType *CONTEXT_TYPE;
static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_error;
static ERL_NIF_TERM atom_out_of_memory;
static ERL_NIF_TERM atom_arg_wrong_size;
static ERL_NIF_TERM atom_public_key_failure;
static ERL_NIF_TERM atom_sign_failure;
static ERL_NIF_TERM atom_recovery_failure;

static ERL_NIF_TERM sign(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    secp256k1_context *ctx = NULL;
    ErlNifBinary message;
    ErlNifBinary private_key;
    ErlNifBinary output;
    ERL_NIF_TERM ret;
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    if (!enif_is_binary(env, argv[1]) || !enif_inspect_binary(env, argv[1], &private_key) || private_key.size != 32) {
        return enif_make_tuple2(env, atom_error, atom_arg_wrong_size);
    }
    if (!enif_is_binary(env, argv[0]) || !enif_inspect_binary(env, argv[0], &message) || message.size != 32) {
        return enif_make_tuple2(env, atom_error, atom_arg_wrong_size);
    }
    if (!enif_alloc_binary(65, &output)) {
        return enif_make_tuple2(env, atom_error, atom_out_of_memory);
    }
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if(!ctx) {
        enif_release_binary(&output);
        return enif_make_tuple2(env, atom_error, atom_out_of_memory);
    }
    if(secp256k1_ecdsa_sign_recoverable(ctx, (secp256k1_ecdsa_recoverable_signature*)output.data, message.data, private_key.data, NULL, NULL)) {
        secp256k1_context_destroy(ctx);
        ret = enif_make_binary(env, &output);
        enif_release_binary(&output);
        return enif_make_tuple2(env, atom_ok, ret);
    } else {
        secp256k1_context_destroy(ctx);
        enif_release_binary(&output);
        return enif_make_tuple2(env, atom_error, atom_sign_failure);
    }
}

static ERL_NIF_TERM recover(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    secp256k1_context *ctx = NULL;
    ErlNifBinary signature;
    ErlNifBinary message;
    ErlNifBinary output;
    ERL_NIF_TERM ret;
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    if (!enif_is_binary(env, argv[1]) || !enif_inspect_binary(env, argv[1], &signature) || signature.size != 65) {
        return enif_make_tuple2(env, atom_error, atom_arg_wrong_size);
    }
    if (!enif_is_binary(env, argv[0]) || !enif_inspect_binary(env, argv[0], &message) || message.size != 32) {
        return enif_make_tuple2(env, atom_error, atom_arg_wrong_size);
    }
    if (!enif_alloc_binary(64, &output)) {
        return enif_make_tuple2(env, atom_error, atom_out_of_memory);
    }
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if(secp256k1_ecdsa_recover(ctx, (secp256k1_pubkey*)output.data, (secp256k1_ecdsa_recoverable_signature* )signature.data, message.data)) {
        secp256k1_context_destroy(ctx);
        ret = enif_make_binary(env, &output);
        enif_release_binary(&output);
        return enif_make_tuple2(env, atom_ok, ret);
    } else {
        secp256k1_context_destroy(ctx);
        enif_release_binary(&output);
        return enif_make_tuple2(env, atom_error, atom_recovery_failure);
    }
}

static ERL_NIF_TERM create_public_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary input;
    ErlNifBinary output;
    ERL_NIF_TERM ret;
    secp256k1_context *ctx = NULL;
    if (argc != 1) {
        return enif_make_badarg(env);
    }
    if (!enif_is_binary(env, argv[0]) || !enif_inspect_binary(env, argv[0], &input) || input.size != 32) {
        return enif_make_tuple2(env, atom_error, atom_arg_wrong_size);
    }
    if (!enif_alloc_binary(64, &output)) {
        return enif_make_tuple2(env, atom_error, atom_out_of_memory);
    }
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if(!ctx) {
        enif_release_binary(&output);
        return enif_make_tuple2(env, atom_error, atom_out_of_memory);
    }
    if(secp256k1_ec_pubkey_create(ctx, (secp256k1_pubkey*)output.data, input.data)) {
        secp256k1_context_destroy(ctx);
        ret = enif_make_binary(env, &output);
        enif_release_binary(&output);
        return enif_make_tuple2(env, atom_ok, ret);
    } else {
        secp256k1_context_destroy(ctx);
        enif_release_binary(&output);
        return enif_make_tuple2(env, atom_error, atom_public_key_failure);
    }
}

static ERL_NIF_TERM compress_public_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary input;
    ErlNifBinary output;
    ERL_NIF_TERM ret;
    size_t out_size = 33;
    secp256k1_context *ctx = NULL;
    if (argc != 1) {
        return enif_make_badarg(env);
    }
    if (!enif_is_binary(env, argv[0]) || !enif_inspect_binary(env, argv[0], &input) || input.size != 64) {
        return enif_make_tuple2(env, atom_error, atom_arg_wrong_size);
    }
    if (!enif_alloc_binary(33, &output)) {
        return enif_make_tuple2(env, atom_error, atom_out_of_memory);
    }
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if(!ctx) {
        enif_release_binary(&output);
        return enif_make_tuple2(env, atom_error, atom_out_of_memory);
    }
    if(secp256k1_ec_pubkey_serialize(ctx, output.data, &out_size, (secp256k1_pubkey*)input.data, SECP256K1_EC_COMPRESSED)) {
        secp256k1_context_destroy(ctx);
        ret = enif_make_binary(env, &output);
        enif_release_binary(&output);
        return enif_make_tuple2(env, atom_ok, ret);
    } else {
        secp256k1_context_destroy(ctx);
        enif_release_binary(&output);
        return enif_make_tuple2(env, atom_error, atom_public_key_failure);
    }
}

static void free_context_resource(ErlNifEnv *env, void *obj) {
    int *context_num = (int *) enif_priv_data(env);
    (*context_num)--;
}

static inline int init_context_resource(ErlNifEnv *env) {
    const char *mod = "Elixir.ExSecp256k1";
    const char *name = "Context";
    int flags = ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER;

    CONTEXT_TYPE = enif_open_resource_type(env, mod, name, free_context_resource, (ErlNifResourceFlags) flags, NULL);
    if (CONTEXT_TYPE == NULL) return -1;
    return 0;
}


static int init_nif(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info) {
    if (init_context_resource(env) == -1) {
        return -1;
    }
    int *context_num = (int *) enif_alloc(sizeof(int));
    (*context_num) = 0;
    *priv_data = (void *) context_num;
    atom_ok = enif_make_atom(env, "ok");
    atom_error = enif_make_atom(env, "error");
    atom_out_of_memory = enif_make_atom(env, "out_of_memory");
    atom_arg_wrong_size = enif_make_atom(env, "arg_wrong_size");
    atom_public_key_failure = enif_make_atom(env, "public_key_failure");
    atom_sign_failure = enif_make_atom(env, "sign_failure");
    atom_recovery_failure = enif_make_atom(env, "recovery_failure");
    return 0;
}

static void destroy_inf(ErlNifEnv *env, void *priv_data) {
    if (priv_data) {
        enif_free(priv_data);
    }
}

static ErlNifFunc ic_sec_nif_funcs[] =
{
    {"create_public_key_nif", 1, create_public_key},
    {"compress_public_key_nif", 1, compress_public_key},
    {"recover_nif", 2, recover, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"sign_nif",    2, sign,ERL_NIF_DIRTY_JOB_CPU_BOUND},
};

ERL_NIF_INIT(Elixir.ExSecp256k1, ic_sec_nif_funcs, init_nif, NULL, NULL, destroy_inf)
