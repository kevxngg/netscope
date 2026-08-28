# Trabajar con git en este repo

Repositorio: `github.com/kevxngg/netscope`

## Subir cambios (el día a día)

Un solo comando. Cambia solo el texto entre comillas:

**PowerShell** (terminal por defecto de VSCode en Windows):

```powershell
git add -A; git commit -m "describe aqui tu cambio"; git push
```

**Git Bash:**

```bash
git add -A && git commit -m "describe aqui tu cambio" && git push
```

> En **PowerShell 5.1 el `&&` no existe** (da error de sintaxis): hay que
> encadenar con `;`. En Git Bash sí funciona `&&`. Mira el nombre en la pestaña
> del terminal si no estás seguro de cuál tienes.

`git add -A` sube todo lo modificado de golpe. El [`.gitignore`](.gitignore) ya
excluye lo que no debe subir (`venv/`, `netscope.db`, `__pycache__/`), pero si
alguna vez dejas algo sensible en la carpeta —un token, una captura de red—
repasa `git status` antes de commitear: `-A` no pregunta.

## Ver qué tienes pendiente

```powershell
git status; git log origin/main..main --oneline
```

Si el segundo comando no imprime nada, no hay commits sin subir.

## Autenticación

Cuando `git push` pida contraseña **no es la de tu cuenta de GitHub**: es un
*Personal Access Token*. Se crea en GitHub → Settings → Developer settings →
Personal access tokens → *Generate new token (classic)*, marcando el permiso
`repo`. Ese token se pega donde pide la contraseña.

## Identidad (ya configurada)

```
user.name   kevxngg
user.email  kevxngg@gmail.com
```

Comprobar en cualquier momento:

```powershell
git config user.name; git config user.email
```

> **Importante:** el email debe ser el de tu cuenta de GitHub. Si no coincide,
> GitHub trata esos commits como de otra persona y **no cuentan en tu gráfico de
> contribuciones**. Ya pasó una vez: los primeros 30 commits de este repo se
> hicieron con el texto de ejemplo `TU_CORREO_DE_GITHUB` sin sustituir, y hubo
> que reescribir toda la historia para arreglarlo.

## Trabajar en una rama

Para un cambio grande que quieras probar antes de que toque `main`:

```powershell
git checkout -b nombre-de-la-rama
# ...trabajas y commiteas normal...
git push -u origin nombre-de-la-rama
```

Cuando esté probado, fusionar y limpiar:

```powershell
git checkout main; git merge --no-ff nombre-de-la-rama; git push
git branch -d nombre-de-la-rama; git push origin --delete nombre-de-la-rama
```

## Deshacer

```powershell
git restore archivo.py              # descartar cambios no commiteados de un archivo
git restore .                       # descartar TODOS los cambios no commiteados
git reset --soft HEAD~1             # deshacer el ultimo commit, conservando los cambios
git revert <hash>                   # commit nuevo que deshace uno ya subido (seguro)
```

`git revert` es lo correcto para deshacer algo **ya subido**: no reescribe la
historia. Evita `reset --hard` y `push --force` salvo que sepas exactamente por
qué los necesitas — cambian los hashes y rompen el repo a quien lo haya clonado.
