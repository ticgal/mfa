# Auditoría de seguridad de MFA — 2 de octubre de 2026

**Resultado:** la versión local 2.0.2 conserva vías para eludir el segundo factor. No debe considerarse una barrera MFA suficiente hasta corregir y volver a verificar los hallazgos altos. Se identifican **3 hallazgos altos y 3 medios**, más observaciones de endurecimiento. La gravedad es cualitativa; no se ha calculado CVSS.

## Alcance y limitaciones

- Revisión completa de `setup.php`, `hook.php`, los dos controladores de `front/`, las tres clases de `inc/` y la plantilla Twig; contraste con la autenticación, sesiones, CSRF, TOTP, notificaciones y dependencias presentes en este workspace GLPI 11.0.9.
- Entorno autorizado: contenedores `glpi11.0.9` y `mariadb11.0.9`, HTTP local en el puerto **8090**. El montaje del contenedor coincide con este workspace.
- El código declara **2.0.2**, pero la base de datos registra **2.0.1, estado 2 (`NOTINSTALLED`)**. No existen `glpi_plugin_mfa_configs` ni `glpi_plugin_mfa_mfas`. Las notificaciones, la API y la obligatoriedad global de 2FA están desactivadas en la configuración leída. Esto no determina las políticas por perfil, entidad o grupo.
- Por ese estado no se realizó una explotación HTTP completa con el plugin activo. No se instaló ni activó el plugin, no se modificaron usuarios ni configuración y no se enviaron correos. Las consultas de aplicación se realizaron mediante la conexión configurada en GLPI.
- Las pruebas aisladas ejecutan métodos reales del plugin con persistencia simulada; las pruebas de limitación utilizan el Symfony instalado y una caché en memoria. No equivalen a una prueba de carga del despliegue.
- Las conclusiones corresponden al código local, incluido el núcleo local consultado; no afirman que otras versiones o instalaciones tengan idéntico comportamiento.

## Hallazgos

| ID | Gravedad | Hallazgo | Evidencia |
| --- | --- | --- | --- |
| MFA-01 | Alta | El login original permite evitar el plugin | Trazado de código |
| MFA-02 | Alta | La preautenticación del plugin habilita el alta de TOTP nativo | Trazado y aceptación del controlador nativo con identidad sintética |
| MFA-03 | Alta | Un fallo al emitir el OTP conserva una sesión autenticada | Reproducción aislada del controlador real |
| MFA-04 | Media | El OTP no se consume atómicamente | Reproducción aislada de concurrencia y fallo de borrado |
| MFA-05 | Media | El límite de intentos pierde actualizaciones concurrentes | Reproducción con métodos reales y Symfony instalado |
| MFA-06 | Media | El OTP queda visible en la cola de notificaciones | Trazado de persistencia y comprobación de la política de divulgación |

### MFA-01 — El segundo factor depende de la acción del formulario

**Referencias:** `hook.php:67-85`, `setup.php:66-78`; contraste con `front/login.php:69` y `src/Auth.php:1114-1143,1182` del núcleo.

El hook `DISPLAY_LOGIN` cambia `loginForm.action` mediante JavaScript. El plugin no establece en el servidor una obligación equivalente para el acceso por `/front/login.php`. Esa ruta llama directamente a `Auth::login()`, que comprueba el MFA nativo y termina inicializando la sesión; no consulta la política de este plugin.

**Condiciones e impacto:** un atacante con contraseña válida de un usuario protegido exclusivamente por este plugin puede enviar el formulario a la ruta original y obtener una sesión sin OTP. El token CSRF y la cookie de prueba se obtienen visitando el login normalmente. Las cuentas protegidas efectivamente por TOTP nativo siguen sujetas a ese control.

**Reproducción pendiente en instalación activa:** con una cuenta de pruebas sin TOTP nativo y con MFA del plugin obligatorio, obtener el formulario y enviar sus credenciales y token CSRF a `/front/login.php`; comprobar después el acceso a un recurso autenticado sin enviar ningún código.

**Corrección:** imponer la política en el servidor para todas las vías de autenticación cubiertas. Diseñar una integración del plugin con el ciclo de autenticación de GLPI que impida conceder acceso antes del segundo factor. La alternativa es usar el MFA nativo obligatorio. Cambiar el JavaScript o bloquear una única URL no resuelve por sí solo la cobertura. No modificar el núcleo como parche local.

### MFA-02 — El estado pendiente por correo autoriza un alta de TOTP

**Referencias:** `front/mfa.form.php:145-167`; núcleo `src/Glpi/Controller/Security/MFAController.php:58-73,98-156`, `src/Glpi/Security/TOTPManager.php:600-618`, `templates/pages/2fa/macros.html.twig:135-171` y `src/Auth.php:1048-1057`.

Antes de validar el correo, el plugin escribe `$_SESSION['mfa_pre_auth']` con el formato del MFA nativo. `/MFA/Setup` interpreta ese estado como autorización suficiente para iniciar el alta cuando el usuario no tiene TOTP. La pantalla genera un secreto y los tokens CSRF/IDOR correspondientes. `/MFA/Verify` acepta un código calculado con ese nuevo secreto, lo registra y marca `mfa_success`, que el login original acepta para completar la sesión.

**Condiciones e impacto:** tras superar solo la contraseña en el flujo del plugin, un atacante puede intentar registrar su propio segundo factor sin conocer el OTP enviado al correo. Además del acceso, el registro puede dejar el TOTP bajo su control. Esta vía debe corregirse aunque se cierre el envío directo del hallazgo MFA-01.

**Validación:** el controlador nativo real devolvió una respuesta de alta con estado 200 al recibir una preautenticación de esa forma, usando un ID sintético inexistente y sin usuario autenticado. No se ejecutó el renderizado del secreto ni su registro. La cadena completa de alta y acceso está sustentada por el código, pendiente de reproducción HTTP con una cuenta de pruebas.

**Corrección:** mantener un estado privado del plugin, ligado al desafío y con caducidad. No publicar `mfa_pre_auth` utilizable por el MFA nativo mientras falte el código por correo. Realizar la transferencia al mecanismo de finalización del núcleo únicamente después de validar y consumir el desafío. Revisar conjuntamente las rutas de alta, verificación y recuperación nativas.

### MFA-03 — La emisión del código puede fallar después de autenticar

**Referencias:** `front/mfa.form.php:108,141,163`; `inc/mfa.class.php:177-206`; núcleo `src/Auth.php:1182` y `src/Session.php:123-165`.

`Auth::login()` ya crea una sesión autenticada. El plugin consulta configuración y emite el código antes de ejecutar `Session::destroy()`. No hay una protección que garantice deshacer la autenticación si una de esas operaciones lanza una excepción.

**Condiciones e impacto:** un error de consulta, inserción, plantilla o procesamiento de notificación en ese intervalo puede terminar la petición dejando la sesión autenticada. Requiere credenciales válidas y una condición de fallo; no se ha demostrado que un atacante pueda provocar cualquiera de esos errores a voluntad.

**Validación:** al ejecutar el controlador real con una excepción simulada en la consulta inicial de `issueCode()`, el estado conservó `glpiID` y no tenía `mfa_success`. El resultado demuestra el orden inseguro; la persistencia HTTP se debe verificar en una instalación activa mediante inyección controlada de fallos.

**Corrección:** separar la comprobación de credenciales de la concesión de sesión. No mantener privilegios mientras se consulta, genera o notifica el desafío. Cualquier excepción debe dejar al usuario sin autenticar. Un `finally` puede ayudar a asegurar limpieza, pero no sustituye una integración correcta de la autenticación.

### MFA-04 — Verificar y consumir el código son operaciones separadas

**Referencias:** `inc/mfa.class.php:219-245`; emisión y esquema en `177-190,260-266`.

El método lee la fila, comprueba la caducidad, valida el hash y finalmente borra. Devuelve `true` sin verificar el resultado del borrado. Dos solicitudes que ya hayan leído y comprobado la misma fila pueden aceptar el mismo OTP. Un fallo de borrado también permite un éxito sin consumo.

**Condiciones e impacto:** se necesita un OTP válido y preautenticación de la cuenta; no es una forma de adivinar códigos. La serialización de una misma sesión PHP no protege solicitudes de sesiones distintas. El desafío solo está ligado al usuario, lo que permite que estados pendientes distintos consulten el mismo código actual.

**Validación:** dos ejecuciones intercaladas de `verifyCode()` aceptaron el mismo código. Otra prueba forzó `delete()` a devolver `false`: la verificación devolvió `true` y la fila permaneció. La repetición secuencial normal sí fue rechazada.

**Corrección:** usar un desafío aleatorio ligado a la sesión, y consumo transaccional o condicional que garantice un único ganador. El éxito requiere confirmar exactamente una transición de pendiente a consumido. Serializar también la emisión; el índice actual sobre `users_id` no es único y las emisiones simultáneas pueden crear múltiples filas.

### MFA-05 — El limitador no usa bloqueo compartido

**Referencias:** `inc/mfa.class.php:62-86`; `vendor/symfony/rate-limiter/RateLimiterFactory.php:33-52` y `Policy/SlidingWindowLimiter.php:52-126`.

Se construye `RateLimiterFactory` sin `LockFactory`. La ventana se lee y se vuelve a guardar sin exclusión mutua. Solicitudes concurrentes pueden leer el mismo contador y sobrescribir sus incrementos, aunque cada operación individual de caché funcione correctamente.

**Condiciones e impacto:** se necesitan varias sesiones pendientes de la misma cuenta. El máximo declarado de cinco intentos por usuario deja de estar garantizado; no se ha medido el aumento máximo de intentos en el servidor real ni se afirma que permita fuerza bruta ilimitada.

**Validación:** seis llamadas secuenciales permitieron **5/6**. Seis llamadas con lecturas intercaladas permitieron **6/6**, ejecutando `PluginMfaMfa::consumeAttempt()` y el Symfony instalado con caché aislada.

**Corrección:** añadir bloqueo compartido por cuenta adecuado a todos los procesos/nodos del despliegue o un contador realmente atómico. La sincronización debe cubrir también el reinicio del contador.

### MFA-06 — El código en claro se almacena y puede consultarse en la cola

**Referencias:** `inc/mfa.class.php:202-206`, `inc/notificationtargetmfa.class.php:35-78`; núcleo `src/NotificationMailing.php:176-200`, `src/NotificationTarget.php:1075-1078` y `src/QueuedNotification.php:65-85,415-435`.

El hash protege la tabla del plugin, pero la notificación incorpora el OTP en claro. La implementación de correo copia ese contenido a `glpi_queuednotifications`. El target del plugin no sobrescribe `canNotificationContentBeDisclosed()`, cuyo valor heredado es `true`, por lo que GLPI no aplica la ocultación nativa de contenido sensible.

**Condiciones e impacto:** un lector autorizado de la cola, dentro del alcance de entidades que pueda consultar, o alguien con lectura de la base de datos puede obtener códigos aún vigentes. Para completar una autenticación sigue siendo necesario superar el primer factor. No es una divulgación anónima.

**Validación:** la clase real devolvió `true` para la divulgación de `securitycodegenerate`, y no declaró eventos de envío inmediato. La persistencia y presentación se verificaron en el código del núcleo. Una prueba adicional de ocultación mediante `QueuedNotification` no pudo completarse porque falta la tabla del plugin; no se generó ningún correo.

**Corrección:** sobrescribir `canNotificationContentBeDisclosed()` para impedir mostrar este evento por las vistas y APIs que respetan esa política. Revisar envío inmediato, retención y permisos de la cola. Ocultar en la interfaz no protege frente a lectura directa de base de datos: si ese es el objetivo, hay que resolver también la persistencia del OTP en claro. El changelog debe reflejar esa limitación del hash.

## Observaciones adicionales

- **Emisión sin límite propio:** cada login válido elimina el desafío anterior y solicita otro correo. Limitar reenvíos por cuenta/origen para evitar inundación de correo e invalidación repetida del código legítimo. No se ejecutaron envíos ni pruebas de carga.
- **Preautenticación sin caducidad explícita ni ID de desafío:** la caducidad de diez minutos protege la fila, pero no expira el estado que prueba la contraseña. Vincular ambos y evitar que una sesión pendiente antigua use un código generado por un intento posterior.
- **Fallos de entrega no comprobados:** no se valida el resultado de persistir o notificar el código. Notificaciones desactivadas, falta de dirección o cola retrasada pueden dejar al usuario sin un código utilizable. Esto es principalmente disponibilidad; no equivale por sí solo a un bypass.
- **Auditoría de eventos:** `Auth::login()` registra éxito y actualiza el último acceso antes de completar el OTP. Conviene distinguir contraseña aceptada de autenticación completa y registrar fallos/bloqueos de MFA sin incluir secretos.
- **Limpieza incoherente:** el cron se registra con antigüedad de cinco minutos, mientras la verificación anuncia diez. Puede eliminar códigos antes del TTL esperado. Unificar la política.
- **Compatibilidad:** persisten clases legacy en `inc/`, comprobaciones de `2fa_secret` que no corresponden al almacenamiento actual gestionado por `TOTPManager`, y `data-submit-once` en un flujo con redirección. No se clasifican como vulnerabilidades autónomas sin evidencia adicional; probar la UI al instalar.

## Controles que sí están presentes

- Generación con `random_int()`, hash con `password_hash()` y comparación mediante `password_verify()`.
- Consulta por usuario, caducidad evaluada con reloj de base de datos y rechazo de valores vacíos.
- Conversión del código recibido a escalar: el array de operadores descrito en el changelog ya no se entrega al constructor de consultas.
- Token CSRF en el formulario. La estrategia `NO_CHECK` del firewall no convierte la ruta en stateless y no elimina por sí sola la comprobación CSRF del núcleo.
- Edición de configuración protegida con `Session::checkRight('config', UPDATE)` y comprobación del objeto.
- Primer paso del controlador con `remember_me=false` para evitar emitir esa cookie anticipadamente dentro de esa ruta. Esto no subsana MFA-01.
- No se identificó una inyección SQL o XSS directa en los puntos revisados; no constituye una garantía sobre código fuera del alcance.

## Comprobaciones ejecutadas y siguientes criterios de aceptación

Los **7 archivos PHP** del plugin superaron `php -l`. No se modificó PHP, JavaScript ni Twig. No fue necesario limpiar caché Twig.

Las pruebas aisladas quedaron en `/tmp/mfa-audit-20261002.php` y `/tmp/mfa-limiter-audit-20261002.php`; son auxiliares temporales y no forman parte del plugin. Comprobaron usuario incorrecto, código incorrecto/vacío, caducidad, éxito y repetición secuencial, además de los fallos descritos. El test de caducidad simula el resultado SQL; no valida por sí mismo el reloj de MariaDB.

Prioridad de corrección: **cobertura del servidor y separación del estado MFA (01–02), ausencia de sesión autenticada ante fallos (03), consumo y limitación atómicos (04–05), confidencialidad de notificaciones (06)**.

Antes de cerrar la auditoría tras corregir, ejecutar pruebas HTTP con el plugin instalado: login directo y del plugin, acceso antes del OTP, rutas TOTP nativas, OTP correcto/incorrecto/caducado/reutilizado, sesiones paralelas, fallo de base de datos/notificación, CSRF ausente o incorrecto, permisos de configuración, lectura de cola y cookie «recordarme». Incluir las autenticaciones externa/LDAP/correo y las APIs que se declaren dentro de la cobertura. Mantener el núcleo sin modificaciones.

Como referencia metodológica, [OWASP: Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) recomienda proteger el ciclo completo de MFA, incluidos los mecanismos alternativos y de recuperación. Los hallazgos anteriores proceden del código local y de las pruebas descritas, no de atribuir vulnerabilidades publicadas al plugin.
