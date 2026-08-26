# Subir esto a GitHub — paso a paso

Tu repo ya existe en `github.com/kevxngg/netscope` con el código viejo. Lo que
cambia aquí es que se **añade** la carpeta `core/` y dos guías. La forma limpia
de subirlo, conservando el historial del repo, es esta.

## Camino recomendado (conserva el historial)

Abre una terminal (la de VSCode sirve: menú *Terminal → New Terminal*).

```bash
# 1. Clona tu repo actual en una carpeta nueva (trae todo el historial)
git clone https://github.com/kevxngg/netscope.git
cd netscope

# 2. Copia SOLO lo nuevo desde el zip descomprimido a esta carpeta:
#      - la carpeta  core/
#      - los archivos INTEGRACION.md  y  GIT.md
#    (puedes arrastrarlos en VSCode o en el explorador de archivos)

# 3. Primer commit: el núcleo nuevo
git add core/
git commit -m "feat(core): capa de datos por identidad y motor de resolución

Reemplaza el modelo basado en MAC por identidades persistentes.
La MAC pasa a ser una señal más; añade site_id, señales con peso,
observaciones efímeras y tráfico agregado por ventana. Resuelve el
problema de MAC randomizada: reconexiones de un mismo equipo colapsan
en una sola identidad."

# 4. Segundo commit: la documentación
git add INTEGRACION.md GIT.md
git commit -m "docs: guía de integración de la Fase 1 y guía de git"

# 5. Sube todo
git push origin main
```

Si tu rama principal se llama `master` en vez de `main`, cambia la última línea
por `git push origin master`. Para saberlo: `git branch` te muestra la actual.

## Si es la primera vez que usas git en esta máquina

Antes del paso 3, identifícate una vez (usa el correo de tu cuenta de GitHub):

```bash
git config --global user.name "kevxngg"
git config --global user.email "TU_CORREO_DE_GITHUB"
```

Al hacer `git push`, GitHub te pedirá autenticación. Si te pide contraseña, **no
es la de tu cuenta**: es un *Personal Access Token*. Se crea en
GitHub → Settings → Developer settings → Personal access tokens → *Generate new
token (classic)*, con el permiso `repo` marcado. Pega ese token como contraseña.

## Alternativa: no tienes el repo clonado y quieres subir esta carpeta tal cual

Solo si NO te importa el historial anterior (lo sobrescribe):

```bash
cd netscope           # la carpeta descomprimida del zip
git init
git add .
git commit -m "feat: NetScope con núcleo de identidad (Fase 1)"
git branch -M main
git remote add origin https://github.com/kevxngg/netscope.git
git push -u origin main --force
```

El `--force` pisa lo que haya en GitHub. Úsalo solo si estás seguro.

## Comprobar que subió bien

```bash
git log --oneline -5      # deberías ver tus commits nuevos arriba
git status                # "nothing to commit, working tree clean"
```
