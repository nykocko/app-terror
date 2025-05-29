// Carga las variables de entorno desde el archivo .env
require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs"); // Para hashing de contraseñas
const jwt = require("jsonwebtoken"); // Para JSON Web Tokens

const app = express();
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// Verifica si las variables de entorno están configuradas
if (!MONGODB_URI) {
  console.error(
    "❌ ERROR: La variable de entorno MONGODB_URI no está definida en tu archivo .env"
  );
  console.error(
    "Asegúrate de que tu .env contenga: MONGODB_URI=mongodb+srv://..."
  );
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error(
    "❌ ERROR: La variable de entorno JWT_SECRET no está definida en tu archivo .env"
  );
  console.error(
    "Asegúrate de que tu .env contenga: JWT_SECRET=tu_secreto_largo_y_aleatorio"
  );
  process.exit(1);
}
if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
  console.error(
    "❌ ERROR: Las variables de entorno ADMIN_USERNAME o ADMIN_PASSWORD no están definidas en tu archivo .env"
  );
  console.error(
    "Asegúrate de que tu .env contenga: ADMIN_USERNAME=admin, ADMIN_PASSWORD=tu_contraseña_fuerte"
  );
  process.exit(1);
}

// Middleware
app.use(cors());
app.use(express.json());

// --- Define el esquema y el modelo de Mongoose para Historias ---
const historiaSchema = new mongoose.Schema({
  nombre: { type: String, default: "Anónimo" },
  email: { type: String, required: true },
  titulo: { type: String, required: true },
  historia: { type: String, required: true },
  categoria: { type: String, default: "Sin categoría" },
  fecha: { type: Date, default: Date.now },
  aprobada: { type: Boolean, default: false },
});
const Historia = mongoose.model("Historia", historiaSchema);

// --- Esquema y Modelo para Usuario Admin ---
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

// Hash de la contraseña antes de guardar el usuario
userSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

const User = mongoose.model("User", userSchema);

// --- Middleware de Autenticación JWT ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Formato: Bearer TOKEN

  if (token == null) {
    console.log("Intento de acceso a ruta protegida sin token.");
    return res
      .status(401)
      .json({ message: "Acceso denegado. Token no proporcionado." });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log("Token inválido:", err.message);
      return res.status(403).json({ message: "Token inválido o expirado." });
    }
    req.user = user; // Guarda la información del usuario en la solicitud
    next(); // Permite que la solicitud continúe
  });
};

// --- Rutas de API ---

// RUTA POST para enviar una nueva historia (¡NO REQUIERE AUTENTICACIÓN!)
app.post("/api/historias", async (req, res) => {
  console.log("Solicitud POST recibida para /api/historias");
  try {
    const { nombre, email, titulo, historia, categoria } = req.body;

    if (!titulo || !historia || !email) {
      return res
        .status(400)
        .json({ message: "Título, historia y email son campos requeridos." });
    }

    const nuevaHistoria = new Historia({
      nombre: nombre,
      email: email,
      titulo: titulo,
      historia: historia,
      categoria: categoria || "Sin categoría",
    });

    await nuevaHistoria.save();
    console.log("Historia guardada exitosamente:", nuevaHistoria._id);
    res
      .status(201)
      .json({ message: "Historia enviada con éxito", historia: nuevaHistoria });
  } catch (error) {
    console.error("Error al guardar la historia:", error);
    res
      .status(500)
      .json({
        message: "Error interno del servidor al guardar la historia",
        error: error.message,
      });
  }
});

// RUTA GET para obtener historias (con paginación, búsqueda y filtrado)
// ¡Solo muestra historias aprobadas! (¡NO REQUIERE AUTENTICACIÓN!)
app.get("/api/historias", async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 9;
    const searchTerm = req.query.search;
    const categoryFilter = req.query.category;
    const sortBy = req.query.sortBy || "reciente";

    let query = { aprobada: true }; // <--- SOLO HISTORIAS APROBADAS

    if (searchTerm) {
      query.$and = [
        { aprobada: true },
        {
          $or: [
            { titulo: { $regex: searchTerm, $options: "i" } },
            { historia: { $regex: searchTerm, $options: "i" } },
          ],
        },
      ];
      delete query.aprobada;
    }
    if (
      categoryFilter &&
      categoryFilter !== "" &&
      categoryFilter !== "Sin categoría"
    ) {
      query.categoria = categoryFilter;
    }

    let sortOptions = { fecha: -1 };
    if (sortBy === "antiguo") {
      sortOptions = { fecha: 1 };
    } else if (sortBy === "titulo") {
      sortOptions = { titulo: 1 };
    }

    const skip = (page - 1) * limit;

    const totalHistorias = await Historia.countDocuments(query);
    const historias = await Historia.find(query)
      .sort(sortOptions)
      .skip(skip)
      .limit(limit);

    res.status(200).json({
      historias: historias,
      totalHistorias: totalHistorias,
      paginaActual: page,
      totalPaginas: Math.ceil(totalHistorias / limit),
    });
  } catch (error) {
    console.error("Error al obtener las historias paginadas:", error);
    res
      .status(500)
      .json({
        message: "Error al obtener las historias",
        error: error.message,
      });
  }
});

// RUTA GET para obtener las últimas historias (para index.html)
// ¡Solo muestra historias aprobadas! (¡NO REQUIERE AUTENTICACIÓN!)
app.get("/api/historias/ultimas", async (req, res) => {
  try {
    const ultimasHistorias = await Historia.find({ aprobada: true })
      .sort({ fecha: -1 })
      .limit(6);
    res.status(200).json(ultimasHistorias);
  } catch (error) {
    console.error("Error al obtener las últimas historias:", error);
    res
      .status(500)
      .json({
        message: "Error al obtener las últimas historias",
        error: error.message,
      });
  }
});

// RUTA POST para el formulario de contacto (¡NO REQUIERE AUTENTICACIÓN!)
app.post("/api/contacto", async (req, res) => {
  console.log("Solicitud POST recibida para /api/contacto");
  try {
    const { nombre, email, mensaje } = req.body;

    if (!nombre || !email || !mensaje) {
      return res
        .status(400)
        .json({ message: "Nombre, email y mensaje son campos requeridos." });
    }

    console.log(
      `Mensaje de contacto recibido de ${nombre} (${email}): "${mensaje}"`
    );
    res
      .status(200)
      .json({ message: "Mensaje de contacto recibido con éxito." });
  } catch (error) {
    console.error("Error al procesar el mensaje de contacto:", error);
    res
      .status(500)
      .json({
        message:
          "Error interno del servidor al procesar el mensaje de contacto",
        error: error.message,
      });
  }
});

// --- RUTA DE LOGIN PARA ADMINISTRADORES ---
app.post("/api/admin/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    let user = await User.findOne({ username: username });

    // Si el usuario "admin" no existe, lo creamos con la contraseña del .env (hasheada)
    if (!user && username === ADMIN_USERNAME) {
      // NOTA: ADMIN_PASSWORD se hashea automáticamente por el pre-save hook en userSchema
      user = new User({ username: ADMIN_USERNAME, password: ADMIN_PASSWORD });
      await user.save();
      console.log("Admin user created successfully.");
    }

    if (!user) {
      console.log(
        `Intento de login fallido para usuario: ${username} (no encontrado)`
      );
      return res.status(400).json({ message: "Credenciales inválidas." });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      console.log(
        `Intento de login fallido para usuario: ${username} (contraseña incorrecta)`
      );
      return res.status(400).json({ message: "Credenciales inválidas." });
    }

    // Credenciales válidas: Generar token JWT
    const token = jwt.sign(
      { id: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: "1h" } // El token expira en 1 hora
    );

    console.log(`Usuario ${username} ha iniciado sesión con éxito.`);
    res.json({
      message: "Login exitoso",
      token: token,
      username: user.username,
    });
  } catch (error) {
    console.error("Error en el proceso de login:", error);
    res
      .status(500)
      .json({
        message: "Error interno del servidor durante el login",
        error: error.message,
      });
  }
});

// --- Rutas de ADMINISTRACIÓN (¡AHORA PROTEGIDAS CON authenticateToken!) ---

// RUTA GET para obtener TODAS las historias pendientes de aprobación
app.get(
  "/api/admin/historias-pendientes",
  authenticateToken,
  async (req, res) => {
    // <--- PROTEGIDA
    try {
      const historiasPendientes = await Historia.find({ aprobada: false }).sort(
        { fecha: 1 }
      );
      res.status(200).json(historiasPendientes);
    } catch (error) {
      console.error("Error al obtener historias pendientes:", error);
      res
        .status(500)
        .json({
          message: "Error interno del servidor al obtener historias pendientes",
          error: error.message,
        });
    }
  }
);

// RUTA PUT para aprobar una historia por ID
app.put(
  "/api/admin/historias/:id/aprobar",
  authenticateToken,
  async (req, res) => {
    // <--- PROTEGIDA
    try {
      const historiaId = req.params.id;
      const historiaActualizada = await Historia.findByIdAndUpdate(
        historiaId,
        { aprobada: true },
        { new: true }
      );

      if (!historiaActualizada) {
        return res.status(404).json({ message: "Historia no encontrada" });
      }
      console.log(`Historia aprobada: ${historiaActualizada.titulo}`);
      res
        .status(200)
        .json({
          message: "Historia aprobada con éxito",
          historia: historiaActualizada,
        });
    } catch (error) {
      console.error(`Error al aprobar historia ${req.params.id}:`, error);
      res
        .status(500)
        .json({
          message: "Error interno del servidor al aprobar la historia",
          error: error.message,
        });
    }
  }
);

// RUTA PUT para ACTUALIZAR (editar) una historia por ID
app.put("/api/admin/historias/:id", authenticateToken, async (req, res) => {
  // <--- PROTEGIDA
  try {
    const historiaId = req.params.id;
    const { nombre, email, titulo, historia, categoria } = req.body;

    if (!titulo || !historia || !email) {
      return res
        .status(400)
        .json({
          message:
            "Título, historia y email son campos requeridos para la actualización.",
        });
    }

    const historiaActualizada = await Historia.findByIdAndUpdate(
      historiaId,
      {
        nombre: nombre,
        email: email,
        titulo: titulo,
        historia: historia,
        categoria: categoria || "Sin categoría",
      },
      { new: true, runValidators: true }
    );

    if (!historiaActualizada) {
      return res.status(404).json({ message: "Historia no encontrada." });
    }
    console.log(`Historia actualizada: ${historiaActualizada.titulo}`);
    res
      .status(200)
      .json({
        message: "Historia actualizada con éxito",
        historia: historiaActualizada,
      });
  } catch (error) {
    console.error(`Error al actualizar historia ${req.params.id}:`, error);
    res
      .status(500)
      .json({
        message: "Error interno del servidor al actualizar la historia",
        error: error.message,
      });
  }
});

// RUTA DELETE para eliminar una historia por ID
app.delete("/api/admin/historias/:id", authenticateToken, async (req, res) => {
  // <--- PROTEGIDA
  try {
    const historiaId = req.params.id;
    const historiaEliminada = await Historia.findByIdAndDelete(historiaId);

    if (!historiaEliminada) {
      return res.status(404).json({ message: "Historia no encontrada" });
    }
    console.log(`Historia eliminada: ${historiaEliminada.titulo}`);
    res.status(200).json({ message: "Historia eliminada con éxito" });
  } catch (error) {
    console.error(`Error al eliminar historia ${req.params.id}:`, error);
    res
      .status(500)
      .json({
        message: "Error interno del servidor al eliminar la historia",
        error: error.message,
      });
  }
});

// --- Conexión a MongoDB y luego inicio del servidor Express ---
mongoose
  .connect(MONGODB_URI)
  .then(async () => {
    // Usamos async para poder esperar por la creación del admin
    console.log("✅ Conectado a MongoDB Atlas.");

    // CUIDADO: Esto creará el usuario admin cada vez que se inicie el servidor
    // si no existe. Para producción, preferirías un script de creación de usuario.
    // Aquí lo hacemos para que funcione "out-of-the-box".
    let adminUser = await User.findOne({ username: ADMIN_USERNAME });
    if (!adminUser) {
      // NOTA IMPORTANTE: La contraseña ADMIN_PASSWORD se hashea *automáticamente*
      // por el 'pre('save')' hook definido en el userSchema antes de guardarse.
      adminUser = new User({
        username: ADMIN_USERNAME,
        password: ADMIN_PASSWORD,
      });
      await adminUser.save();
      console.log(`✨ Usuario administrador '${ADMIN_USERNAME}' creado.`);
    } else {
      // Opcional: Si el usuario existe, pero la contraseña en .env ha cambiado, actualízala
      // Hacemos un 'compare' para evitar re-hashear y guardar la misma contraseña sin necesidad.
      const isPasswordMatch = await bcrypt.compare(
        ADMIN_PASSWORD,
        adminUser.password
      );
      if (!isPasswordMatch) {
        // Aquí la contraseña de 'adminUser.password' se re-hashea debido al pre-save hook.
        adminUser.password = ADMIN_PASSWORD;
        await adminUser.save();
        console.log(
          `🔄 Contraseña del usuario administrador '${ADMIN_USERNAME}' actualizada.`
        );
      } else {
        console.log(
          `ℹ️ Usuario administrador '${ADMIN_USERNAME}' ya existe y contraseña coincide.`
        );
      }
    }

    app.listen(PORT, () => {
      console.log(`🚀 Servidor Express escuchando en http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error("❌ Error al conectar a MongoDB Atlas:", err.message);
    console.error(
      "Asegúrate de que tu MONGODB_URI en .env sea correcta y que tu red permita la conexión a MongoDB Atlas."
    );
    process.exit(1);
  });
