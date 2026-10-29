# AutoPen Three-Target Docker Lab

This lab provides three disposable **containers that share the host Linux kernel**.
They are separate network targets, but they are not three virtual machines.

- Target A: SSH on TCP 22 with the non-root `autopen-test` account.
- Target B: plain HTTP on TCP 8080 with harmless static content.
- Target C: FTP on TCP 21 with the non-root `autopen-ftp` account and a harmless sample file.

All targets attach only to the internal `autopen-lab` Docker bridge. No ports are
published to host interfaces. The Compose configuration requests the short host bridge
name `aplab0` and the isolated subnet `172.28.50.0/24`.

## Initialize local secrets

From the repository root:

```bash
./lab/init-secrets.sh
```

This creates ignored, mode-`0600` files without displaying their values:

```text
lab/secrets/ssh_password.txt
lab/secrets/ftp_password.txt
data/lab_credentials.txt
```

The SSH candidate list contains two generated incorrect candidates and the generated
Target A password. Target C uses a different password that is not added to that list.

## Build and start

Check free disk space first:

```bash
df -h .
```

Then build and start only this project:

```bash
docker compose -f lab/compose.yaml build
docker compose -f lab/compose.yaml up -d
docker compose -f lab/compose.yaml ps
```

## Obtain current addresses and capture interface

```bash
docker inspect -f '{{.Name}} {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
  autopen-target-a autopen-target-b autopen-target-c

docker network inspect autopen-lab \
  -f '{{index .Options "com.docker.network.bridge.name"}}'

ip -brief link show aplab0
```

Always verify these values before running AutoPen. A route or address is not an
authorization statement.

## Stop and restart

```bash
docker compose -f lab/compose.yaml stop
docker compose -f lab/compose.yaml start
```

## Rotate Target A's password without changing the original candidate list

The following deliberately replaces only Target A's runtime secret. It does not modify
`data/lab_credentials.txt`, so the original candidate list will no longer match afterward:

```bash
umask 077
openssl rand -hex 18 > lab/secrets/ssh_password.txt
chmod 600 lab/secrets/ssh_password.txt
docker compose -f lab/compose.yaml restart target-a
```

No password value is printed.

## Remove only this lab

Remove its containers and dedicated network:

```bash
docker compose -f lab/compose.yaml down
```

Optionally remove only the three locally built images:

```bash
docker compose -f lab/compose.yaml down --rmi local
```

Local ignored secrets and the candidate list are intentionally preserved. Delete those
specific files manually only when they are no longer needed. Do not use broad Docker
pruning commands for this lab.

## Deliberate FTP limitation

TLS is deliberately disabled on Target C for this isolated demonstration. AutoPen's
current FTP rule independently reports only a **potential** cleartext transport issue:
it identifies the FTP service but does not test whether TLS is available or required.

Only use these targets on the isolated lab network and only for the authorized university
demonstration. FTP credential testing is outside this milestone.
