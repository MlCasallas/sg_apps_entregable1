<?php
// Verificar si el método utilizado para enviar el formulario es POST, lo que significa que los datos están siendo enviados correctamente
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // Conectar a la base de datos MySQL
    // Usamos 'localhost' como host, 'root' como usuario y una contraseña vacía 
    // La base de datos que se va a utilizar es 'usuarios_db'
    $conn = new mysqli('localhost', 'root', '', 'usuarios_db');

    // Verificar si la conexión fue exitosa, si falla se muestra un mensaje de error
    if ($conn->connect_error) {
        die("Conexión fallida: " . $conn->connect_error);
    }

    // Capturar y sanitizar los datos del formulario
    // htmlspecialchars() se usa para evitar que caracteres especiales como '<' y '>' causen problemas (prevención de XSS)
    // trim() elimina los espacios en blanco al inicio y al final del texto
    $nombre = htmlspecialchars(trim($_POST['nombre']));
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL); // Sanitiza el correo eliminando caracteres no válidos
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT); // Encripta la contraseña para que no se almacene en texto plano
    $fecha_nacimiento = $_POST['fecha_nacimiento']; // Almacena la fecha de nacimiento tal cual fue ingresada
    $telefono = htmlspecialchars(trim($_POST['telefono'])); // Escapa caracteres especiales y elimina espacios en blanco

    

    // Preparar la consulta SQL usando una consulta preparada para evitar SQL Injection
    // La consulta insertará los datos capturados en la tabla 'usuarios' en la base de datos
    $stmt = $conn->prepare("INSERT INTO usuarios (nombre, email, contraseña, fecha_nacimiento, telefono) VALUES (?, ?, ?, ?, ?)");

    // Enlazar los parámetros a la consulta SQL (la 's' significa que es un string)
    $stmt->bind_param("sssss", $nombre, $email, $password, $fecha_nacimiento, $telefono);

    // Ejecutar la consulta y verificar si fue exitosa
    if ($stmt->execute()) {
        // Si todo va bien, se muestra un mensaje indicando que el usuario fue registrado exitosamente
        echo "Usuario registrado con éxito";
    } else {
        // Si ocurre un error durante la inserción, se muestra un mensaje con el error
        echo "Error: " . $stmt->error;
    }

    // Cerrar la consulta y la conexión a la base de datos
    $stmt->close(); // Cerramos la consulta preparada
    $conn->close(); // Cerramos la conexión a la base de datos
}

?>
