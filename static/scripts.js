



async function getMinecraftProfile(uuid) {
  uuid = uuid.replaceAll("-", "");

  const res = await fetch(
    `https://sessionserver.mojang.com/session/minecraft/profile/${uuid}`
  );

  if (!res.ok) throw new Error(`Mojang API error: ${res.status}`);

  const profile = await res.json();
  const texturesProp = profile.properties.find(p => p.name === "textures");

  const textures = JSON.parse(atob(texturesProp.value));

  return {
    uuid: profile.id,
    username: profile.name,
    skinUrl: textures.textures.SKIN?.url ?? null,
    capeUrl: textures.textures.CAPE?.url ?? null,
  };
}

