# File Integrity Monitor

Herramienta educativa de Python para registrar el estado de una carpeta y detectar
archivos **nuevos, modificados o eliminados** mediante hashes SHA-256.
Funciona sin red, credenciales ni dependencias externas.

**Un cambio no demuestra malware. Una comparación sin cambios no demuestra seguridad.**

## Requisitos

Python 3.10 o superior. La versión inicial está orientada a Linux; las pruebas
de enlaces simbólicos y archivos FIFO se ejecutan en Linux. No necesitas `pip`.

## Demostración rápida

Desde la carpeta del proyecto:

```bash
python3 examples/demo.py
```

La demostración crea una carpeta temporal y una referencia inicial, comprueba que
no hay cambios, modifica un archivo, añade otro y elimina un tercero. Muestra el
informe y limpia sus propios archivos al terminar. No toca tus documentos.

## Uso con una carpeta propia

```bash
# Preparar archivos de demostración
mkdir -p local-data/documents
printf 'mode=demo\n' > local-data/documents/config.txt

# Registrar una referencia inicial confiable
python3 monitor.py baseline local-data/documents local-data/baseline.json

# Comparar sin cambios: devuelve 0
python3 monitor.py check local-data/documents local-data/baseline.json

# Modificar un archivo de demostración
printf 'mode=updated\n' > local-data/documents/config.txt

# Comparar: devuelve 1 porque hay cambios
python3 monitor.py check local-data/documents local-data/baseline.json

# Obtener salida estructurada
python3 monitor.py check local-data/documents local-data/baseline.json --format json
```

La referencia **debe estar fuera** de la carpeta vigilada, para que no se incluya
a sí misma en el siguiente recorrido. Su directorio padre debe existir.
El comando `baseline` nunca reemplaza un archivo existente. Para actualizar una
referencia, investiga primero los cambios y elige otro nombre para conservar la
anterior. No aceptes automáticamente una referencia nueva tras una alerta.

Las rutas relativas parten del directorio desde el que ejecutas el comando.
La herramienta no modifica los archivos vigilados. Solo el comando `baseline`
crea un archivo nuevo en la ruta que indiques.

## Qué compara

- Guarda rutas relativas, tamaño en bytes y hash SHA-256 de cada archivo regular.
- Lee el contenido en bloques de 1 MiB; no carga cada archivo entero en memoria.
- Un archivo con el mismo tamaño pero contenido distinto se marca como modificado.
- Cambiar solo fechas o permisos no se considera modificación de contenido.
- Un cambio de nombre aparece como una eliminación y una incorporación.
- Los directorios vacíos no se registran.
- Se excluye cualquier entrada llamada `.git`, en cualquier nivel, sea carpeta
  o archivo. No hay otras exclusiones automáticas: un `.gitignore` no modifica
  qué archivos analiza el monitor.

## Errores y archivos especiales

Los enlaces simbólicos, incluidos los que apuntan fuera de la carpeta, se rechazan
en lugar de seguirlos. La raíz y la referencia tampoco pueden ser enlaces simbólicos.
Los archivos especiales, como FIFO, sockets y dispositivos, no se admiten.

Un error de lectura o acceso cancela el análisis con salida `2`, sin informe
parcial. También se rechazan referencias JSON inválidas, versiones incompatibles,
claves duplicadas, hashes inválidos y rutas relativas mal formadas.

Se comprueban metadatos antes y después de leer cada archivo para detectar
ciertas modificaciones concurrentes. Esto **no es una instantánea atómica**:
para resultados fiables, detén los procesos que escriben en la carpeta durante
el registro y la comprobación. No se garantiza seguridad ante un adversario que
altere activamente el sistema de archivos durante el recorrido.

## Informes y códigos de salida

El formato predeterminado es texto. Ambos comandos aceptan `--format json`.
En `check`, el JSON contiene `status`, `scanned_files`, `added`, `modified`,
`deleted` y `notice`. Las listas se ordenan por ruta. Los nombres se escapan en
los informes de texto para evitar interpretar caracteres de control.

```json
{
  "status": "changed",
  "scanned_files": 2,
  "added": ["new.txt"],
  "modified": ["config.txt"],
  "deleted": ["obsolete.txt"],
  "notice": "Changes require review; they do not prove malicious activity. The baseline must be trusted."
}
```

| Código | Significado |
| --- | --- |
| `0` | Referencia creada o comparación completada sin cambios. |
| `1` | Comparación completada con cambios. |
| `2` | Error de argumentos, referencia, lectura o recorrido. |

En automatización, conserva esta distinción: `1` significa cambios detectados;
`2` significa que no se pudo completar una comparación confiable.

```bash
python3 monitor.py --help
python3 monitor.py baseline --help
python3 monitor.py check --help
```

## Pruebas

```bash
python3 -m unittest discover -s tests -v
```

GitHub Actions está configurado para Python 3.10 y 3.12 en Ubuntu. La configuración
de CI no implica que se haya ejecutado en GitHub; consulta la pestaña Actions.

```text
monitor.py                   Lógica de hashes, referencias e interfaz de terminal
examples/demo.py             Demostración aislada y repetible
tests/test_monitor.py        Pruebas unitarias y de la CLI
docs/learning-notes.md       Decisiones y ejercicios
.github/workflows/tests.yml Pruebas automatizadas
```

## Alcance y protección de la referencia

Esta herramienta compara archivos con una referencia que tú debes proteger.
Si alguien cambia tanto los archivos como la referencia, la comparación puede
ocultar modificaciones. La referencia no está firmada ni autenticada: guárdala
en un lugar de confianza, con permisos adecuados y respaldo separado.

No detecta malware, no monitoriza continuamente, no envía alertas, no restaura
archivos ni sustituye copias de seguridad. Tampoco verifica propietarios, ACL,
atributos extendidos o la integridad de los directorios. La lista de archivos
se conserva en memoria; carpetas con millones de entradas pueden requerir otro
sistema. El recorrido recursivo falla explícitamente si supera el límite del intérprete.

Las referencias y los informes pueden revelar nombres de archivos. `local-data/`
y `reports/` están ignorados por Git para facilitar la separación de datos locales;
revisa siempre los archivos antes de publicar.

## Desarrollo y licencia

Desarrollado con asistencia de IA. Las [notas de aprendizaje](docs/learning-notes.md)
explican decisiones e incluyen ejercicios sin atribuir trabajo personal al autor.

Licencia [MIT](LICENSE).
