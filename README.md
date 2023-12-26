# mrpack-container

A command line application that turns a Modrinth `.mrpack` file into a container OCI image.
This container is for use on a container runtime such as Podman or Docker, or on an orchestrator such as Kubernetes.

This does not require any container runtime to run, and can be run inside of a container itself.
No mod files or other scripts are executed as part of this operation.

You are responsible for adhering to the licensing requriements of the mod files invovled.
This project is not affiliated with Modrinth.

## Building Images

You need a Modrinth format modpack file (i.e., a `.mrpack` file).
You can find these on [Modrinth](https://modrinth.com/modpacks), or use [packwiz](https://packwiz.infra.link/) to convert other formats of modpack to the Modrinth format.

the `--output-tar` flag is required to specify the output location for a container in TAR format.

```
mrpack-container my-modpack.mrpack --output-tar image.tar
```

You can load and execute the produced image directly:
```
docker load --input image.tar
docker run my-modpack:0.1.0
```

See below for how to use the image to run a server.

## Overriding Settings

### Overriding the Base Image

By default mrpack-container uses [wolfi](wolfi.dev) 's JRE image to provide the base system and Java.
The Mojang version API is used to retreve the correct Java version, and that JVM is used.
You can instead specify your own base image with `--base-image`.
Doing so will disable any Java version checking and just use the image you provide.

## Container Structure

The container places all files resolved from the Modpack in a single container layer.
The minecraft directory is `/opt/minecraft`.
This means that mods are located in `/opt/minecraft/mods`, configuration files in `/opt/minecraft/config`, and so on.

Unlike the normal mod loader installers, mrpack-container does not repackage downloaded JARs into a single JAR.

## Using the Container

You will likely want to bind some extra things into the container at runtime to actually use it.
The EULA is not accepted by default, so you will want to bind your own `eula.txt` into `/opt/minecraft/eula.txt` at runtime.
You may also want to provide settings, as no `server.settings` file is provided.
Minecraft will start without one, and use defaults, but this will result in a server without any allow listing or ops.
You likely want to bind in `/opt/minecraft/whitelist.json` and `/opt/minecraft/ops.json`.
