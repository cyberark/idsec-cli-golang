---
title: Access Space examples
description: Access Space command examples
---

# Access Space examples

### List all accessible assets
```shell linenums="0"
idsec access assets list
```

### List only recently accessed assets
```shell linenums="0"
idsec access assets list-by --recents-only
```

### List only favorite assets
```shell linenums="0"
idsec access assets list-by --favorites-only
```

### List assets filtered by access method (vaulted or zsp)
```shell linenums="0"
idsec access assets list-by --access-method vaulted
```

### List assets with a keyword search and sort
```shell linenums="0"
idsec access assets list-by --search "address contains 10.0.0" --sort address.asc
```

### List assets with a result limit
```shell linenums="0"
idsec access assets list-by --limit 50
```

### Retrieve credentials for an asset
```shell linenums="0"
idsec access assets secret --asset-id your-asset-id
```

### Retrieve credentials with an audit reason
```shell linenums="0"
idsec access assets secret --asset-id your-asset-id --reason "Break-glass troubleshooting"
```
