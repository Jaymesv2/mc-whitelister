kill:
    # #!/usr/bin/env bash
    kill -s KILL $(ps aux | grep oauth-bridge | head -n 1 | tr -s ' ' | cut -d' ' -f2)


generate_spec:
    #!/usr/bin/env bash

    openapi-generator-cli generate \
      -i $LUCKPERMS_OPENAPI_SPEC \
      -g rust \
      -o ./luckperms_api \
      --additional-properties=packageName=luckperms_api,packageVersion=0.1.0,library=reqwest,supportMiddleware=true


upload_image:
    #!/usr/bin/env bash
    $(nix build .#oauth_bridge_container_stream --print-out-paths) | gzip --fast  | skopeo copy docker-archive:/dev/stdin docker://harbor.jaymes.xyz/minecraft/oauth_bridge:0.1.0

#    docker://some_docker_registry/myimage:tag
#
# docker tag qbittorrent-setup:0.1.0 harbor.jaymes.xyz/library/media/qbittorrent_setup:0.1.0
#    docker push harbor.jaymes.xyz/library/media/qbittorrent_setup:0.1.0

