# Notas de aprendizaje

## Decisiones implementadas

- SHA-256 permite comparar contenido sin almacenar una copia de cada archivo.
  Un hash no cifra el contenido ni acredita quién lo creó.
- Las rutas relativas permiten comparar una carpeta movida con la misma referencia.
  Esto también significa que el usuario debe elegir la carpeta correcta.
- La referencia permanece fuera del árbol vigilado para evitar que su propia
  creación aparezca como una modificación.
- El comando de registro crea referencias exclusivamente; no sobrescribe las
  anteriores ni acepta cambios de forma automática.
- Los hashes se calculan por bloques y los resultados se ordenan para facilitar
  comparaciones y pruebas repetibles.
- Los archivos vacíos y binarios se analizan igual que los archivos de texto.
- Los enlaces simbólicos no se siguen; los errores de lectura no se omiten.
  Un informe incompleto puede inducir a una conclusión incorrecta.
- Las comprobaciones de metadatos detectan algunos cambios durante la lectura,
  pero no convierten un recorrido de carpetas en una instantánea atómica.
- La integridad de la referencia es un requisito externo. Esta versión no
  implementa firmas, almacenamiento seguro ni protección frente a un atacante local.

## Ejercicios sugeridos

1. Ejecuta la demostración y explica las tres categorías de cambios.
2. Cambia un archivo conservando su tamaño y observa el resultado.
3. Modifica solo la fecha de un archivo y explica por qué no cambia su hash.
4. Explica por qué una referencia alterada puede ocultar cambios.
5. Diseña una prueba antes de añadir una nueva opción de exclusión.

## Registro personal

Documenta aquí tus propias decisiones, referencias y conclusiones.
Estas notas fueron preparadas con asistencia de IA; no acreditan ejercicios
realizados ni experiencia profesional.
