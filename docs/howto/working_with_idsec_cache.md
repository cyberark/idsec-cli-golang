---
title: Work with Idsec cache
description: Working With Idsec Cache
---

# Work with Idsec cache

The CLI caches login information in the local machine's keystore or, when a keystore does not exist, in an encrypted folder (located in `$HOME/.idsec/cache/keyring`). The cached information is used to run commands until the authentication tokens expire or are otherwise invalidated.

You can set the cache folder with the `IDSEC_KEYRING_FOLDER` env variable. To force Idsec to work only with the filesystem cache, use the `IDSEC_BASIC_KEYRING` environment variable.

The key material that protects the encrypted folder is kept in a separate file outside that folder, located by default in `$HOME/.idsec/keys/keyring.key` and readable only by its owner. You can set its path with the `IDSEC_KEYRING_KEY_FILE` environment variable; the two locations are set independently, and `IDSEC_KEYRING_FOLDER` does not relocate the key file. Both locations need to persist for a cache to survive: removing either one means logging in again. In the container image both live under `/idsec`, so mounting that single path, as the Docker instructions in the README describe, keeps them together.

If you want to ignore the cache when logging in, use the `-f` flag:

```bash linenums="0"
idsec login --force
```

To clear the cache, run `idsec cache clear` or, when using an encrypted folder, remove the files from the `$HOME/.idsec/cache/keyring` folder. Removing the key file invalidates the cache as well. In every case the CLI discards the cache and authenticates again on its next use, as it also does for a cache written by an earlier CLI version, so no error is reported and no action is needed after an upgrade.
