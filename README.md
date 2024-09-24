# mrpack-container

Turn Modrinth modpack (`.mrpack`) files directly into ready-to-use container images.

`mrpack-container` is:
- Fast
- Does not require a JVM
- Does not require a container runtime
- Pure Rust

The resulting containers are:
- Small, usually a few hundred MB depending on mods installed
- Fast to start up, with no downloads on bootup required
- Security focused, running as non-root with the majority of the filesystem immutable

## Warnings

You are responsible for adhering to the licensing requirements of the mod files involved.
This project is not affiliated with Modrinth.
NOT AN OFFICIAL MINECRAFT PRODUCT. NOT APPROVED BY OR ASSOCIATED WITH MOJANG OR MICROSOFT.

**This is pre-Alpha and is under construction.**
In particular, the code quality is awful because this is thrown together.
Many things are not yet supported.

## Installing

Right now you will need to clone this repository with git, and then build the mrpack-container binary with Rust.
You will need to have a [Rust toolchain](https://www.rust-lang.org/tools/install) installed for your platform.

For example:
```bash
git clone https://github.com/JamesLaverack/mrpack-container.git
cd mrpack-container
cargo build --release
```

Or, from inside the `mrpack-container` directory, you can directly build and execute using `cargo run`. 

## Building Images

You need a Modrinth format modpack file (i.e., a `.mrpack` file).
You can find these on [Modrinth](https://modrinth.com/modpacks), or use [packwiz](https://packwiz.infra.link/) to convert other formats of modpack to the Modrinth format.

```bash
mrpack-container --output ./output my-modpack.mrpack
```

The output is in OCI format in the given directory, but not compressed. You can use `tar` to compress it into a single file: `tar cf - -C ./output .`.

You can load and execute the produced image directly with a container runtime.
```bash
tar cf - -C ./output/ . | podman load
```

or use [Skopeo](https://github.com/containers/skopeo) to upload it directly to a container runtime:
```bash
skopeo copy --format=oci oci:./output docker://registry.example.com/my-modpack:latest
```

## Using Images

You will need to mount:
- A Minecraft server JAR from Mojang, of the correct Minecraft version for your mods and loader, usually mounted at `/usr/lib/minecraft/sever.jar`
- A file to accept the Minecraft [EULA](https://www.minecraft.net/en-us/eula), usually a text file containing `eula=true` at `/var/minecraft/eula.txt`.

And you will probably **want** to mount:
- A settings file, usually at `/var/minecraft/server.properties`
- A directory to store the world saves, usually at `/var/minecraft/world`

For example:
```bash
# Minecraft 1.20.1
wget https://piston-data.mojang.com/v1/objects/84194a2f286ef7c14ed7ce0090dba59902951553/server.jar
# Doing this means you are accepting the Minecraft EULA
echo "eula=true" > eula.txt
mkdir world
podman run \
  -p 25565:25565 \
  -v "$(pwd)"/world:/var/minecraft/world \
  -v "$(pwd)"/server.jar:/usr/lib/minecraft/server.jar:ro \
  -v "$(pwd)"/eula.txt:/var/minecraft/eula.txt:ro \
  <container_id>
```
Will run the server and make it available on `localhost:25565`.

## Container Structure

In general:
- `/bin`, `/lib`, `/usr/local/java`, and `/usr/share/doc` are used for system-level dependencies, i.e., Java.
- `/usr/local/minecraft` is used for immutable files to do with the Minecraft install.
- `/var/minecraft` is used for things that are mostly expected to be mutable at runtime.

In detail:
- `/bin` with a simlink for `/bin/java` (to `/usr/local/java/bin/java`)
- `/lib` with the musl Libc library
- `/usr/local/java` with the JVM
- `/usr/local/minecraft/lib` with modloader libraries
- `/usr/share/doc/musl` with copyright information for musl

The files and overrides in the Modrinth file are unpacked into `/var/minecraft`.
Permissions are set as `0755` or `0644`, and most files are owned by root.
Some files, depending on their name, are set as `0777` or `0666` instead, allowing the Minecraft process to write to them.

The container is intended to be run with the main process running as uid `1000` and gid `1000`, therefore a number of directories are owned by that user instead:
- `/var/minecraft`
- `/var/minecraft/config`
- `/var/miencraft/libraries`

## Layers

The container makes extensive use of layering:

- A base layer, of musl from Debian. Including only the shared library and copyright information.
- a JRE
- Your mod loader of choice
- Each download from the mrpack file, one layer per download 
- Overrides from the mrpack file
- Server overrides from the mrpack file
- Permissions changes

