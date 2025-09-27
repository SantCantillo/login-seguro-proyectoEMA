// make-hash.js
const bcrypt = require('bcryptjs');

// Contraseña que quieres convertir en hash
const password = '$4nt14go#';

// Generar hash
const hash = bcrypt.hashSync(password, 12);

// Mostrar resultados
console.log('Hash generado:', hash);
console.log('¿Coincide?', bcrypt.compareSync(password, hash));
