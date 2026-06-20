generate_spec:
    #!/usr/bin/env bash

    openapi-generator-cli generate \
      -i $LUCKPERMS_OPENAPI_SPEC \
      -g rust \
      -o ./luckperms_api \
      --additional-properties=packageName=luckperms_api,packageVersion=0.1.0,library=reqwest
