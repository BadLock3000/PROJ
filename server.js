import express from "express";
import ldap from "ldapjs";
import bodyParser from "body-parser";
import cors from "cors";
import winston from "winston";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { spawn } from "child_process";
import pkg from "pg";
// import { Pool } from "pg";
// import db from "./db";
dotenv.config({ path: "D:\\web\\GNStest\\backend\\.env" });
const { Pool } = pkg;
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} ${level}: ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: "combined.log" }),
  ],
});

const app = express();
app.use(bodyParser.json());
app.use(
  cors({
    origin: ['http://frontend:5173', // Для Docker
    'http://localhost:5173', // Для локальной разработки
    'http://localhost'] ,// Разрешить только этот домен
    
    methods: ["GET", "POST","OPTIONS"], // Разрешить только эти методы
    allowedHeaders: ["Content-Type", "Authorization"], // Разрешить только эти заголовки
  })
);


const LDAP_SERVER = "sipc.miet.ru";
const LDAP_PORT = 389; // Используем порт 389 для LDAP без TLS
const LDAP_BASE = "OU=MIET,DC=sipc,DC=miet,DC=ru";
const LDAP_USER_FILTER = "(sAMAccountName={{username}})";
const JWT_SECRET = "your_jwt_secret";
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});
const query = (text, params) => pool.query(text, params);
const authenticateJWT = (req, res, next) => {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(401).send("Unauthorized");
  }

  jwt.verify(token.split(" ")[1], JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).send("Forbidden");
    }
    req.user = user;
    next();
  });
};

app.get("/check-db", async (req, res) => {
  try {
    const result = await query.query("SELECT NOW()");
    res
      .status(200)
      .send(
        `Database connection successful. Current time: ${result.rows[0].now}`
      );
  } catch (error) {
    logger.error(`Database connection error: ${error.message}`);
    res.status(500).send("Database connection error");
  }
});

app.get("/create-users-table", async (req, res) => {
  try {
    await query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        display_name VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    res.status(200).send("Users table created successfully");
  } catch (error) {
    logger.error(`Error creating users table: ${error.message}`);
    res.status(500).send("Error creating users table");
  }
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    logger.error("Неверный ввод: отсутствует имя пользователя или пароль");
    return res.status(400).send("Неверный ввод");
  }



  app.post('/api/login', async (req, res) => {
    try {
      const { username, password } = req.body;
      
      // 1. Проверка существования пользователя
      const user = await pool.query(
        'SELECT * FROM users WHERE username = $1', 
        [username]
      );
      
      if (user.rows.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
  
      // 2. Проверка пароля (если храните хэш)
      const isValid = await bcrypt.compare(password, user.rows[0].password);
      if (!isValid) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
  
      // 3. Генерация JWT токена
      const token = jwt.sign(
        { userId: user.rows[0].id },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
  
      res.json({ token });
      
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ 
        error: 'Internal server error',
        details: error.message 
      });
    }
  });

  // admin
  // ADMIN_PASSWORD=admin123
  // +++++++++
  if (username === "admin" && password === "admin123") {
    const token = jwt.sign({ username: "admin", role: "admin" }, JWT_SECRET, {
      expiresIn: "1h",
    });

    return res.status(200).json({
      token,
      username: [{ type: "displayName", values: ["Администратор"] }],
    });
  }
  // +++++++++
  logger.info(`Получен запрос на вход для пользователя: ${username}`);

  const client = ldap.createClient({
    url: `ldap://${LDAP_SERVER}:${LDAP_PORT}`,
  });

  const userFilter = LDAP_USER_FILTER.replace("{{username}}", username);
  const userDN = `CN=${username},OU=Students,OU=MIET,DC=sipc,DC=miet,DC=ru`;
  logger.info(`Попытка привязки с DN: ${userDN}`);

  client.bind(`${username}@sipc.miet.ru`, password, (err) => {
    if (err) {
      logger.error(`Ошибка привязки LDAP: ${err.message}`);
      client.unbind();
      return res.status(401).send("Неверное имя пользователя или пароль");
    }

    logger.info(`Успешная привязка с DN: ${userDN}`);

    const searchOptions = {
      scope: "sub",
      filter: userFilter,
      attributes: ["sAMAccountName", "displayName"],
    };

    logger.info(`Поиск с опциями: ${JSON.stringify(searchOptions)}`);
    client.search(LDAP_BASE, searchOptions, (err, searchRes) => {
      if (err) {
        logger.error(`Ошибка поиска LDAP: ${err.message}`);
        client.unbind();
        return res.status(500).send("Внутренняя ошибка сервера");
      }

      searchRes.on("searchEntry", async (entry) => {
        logger.info(`Пользователь ${username} успешно аутентифицирован`);
        logger.info(
          `Атрибуты записи LDAP: ${JSON.stringify(entry.attributes, null, 2)}`
        );

        const sAMAccountName = entry.attributes.find(
          (attr) => attr.type === "sAMAccountName"
        )?.values[0];

        if (sAMAccountName) {
          const token = jwt.sign(
            { username: sAMAccountName, role: "user" },
            JWT_SECRET,
            {
              expiresIn: "1h",
            }
          );

          try {
            // Создаем таблицу, если она не существует
            await query(`
              CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                display_name VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
              )
            `);

            // Вставляем данные в таблицу
            await query(
              "INSERT INTO users (username, display_name) VALUES ($1, $2) ON CONFLICT (username) DO NOTHING",
              [
                sAMAccountName,
                entry.attributes.find((attr) => attr.type === "displayName")
                  ?.values[0],
              ]
            );
            logger.info(
              `Пользователь ${sAMAccountName} успешно записан в базу данных`
            );
          } catch (error) {
            logger.error(`Ошибка записи в базу данных: ${error.message}`);
            return res.status(500).send("Внутренняя ошибка сервера");
          }

          res.status(200).json({ token, username: entry.attributes });
        } else {
          logger.error(`Запись LDAP не содержит sAMAccountName`);
          res.status(500).send("Внутренняя ошибка сервера");
        }
      });

      searchRes.on("error", (err) => {
        logger.error(`Ошибка поиска LDAP: ${err.message}`);
        client.unbind();
        res.status(500).send("Внутренняя ошибка сервера");
      });

      searchRes.on("end", (result) => {
        if (result.status !== 0) {
          logger.error(
            `Поиск LDAP завершился с ошибкой: ${result.errorMessage}`
          );
          client.unbind();
          res.status(500).send("Внутренняя ошибка сервера");
        } else {
          client.unbind();
        }
      });
    });
  });
});
app.get("/get-lab-results", authenticateJWT, async (req, res) => {
  try {
    // Проверяем роль пользователя (если нужно ограничить доступ только для администратора)
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Forbidden: Access denied" });
    }

    // Выполняем запрос к таблице lab_results
    const result = await query(`
      SELECT 
        lab_results.id,
        lab_results.username,
        lab_results.lab_number,
        lab_results.result,
        lab_results.subject,  
        lab_results.created_at,
        users.display_name
      FROM lab_results
      JOIN users ON lab_results.username = users.username
      ORDER BY lab_results.created_at DESC
    `);

    // Возвращаем результаты
    res.status(200).json(result.rows);
  } catch (error) {
    logger.error(`Ошибка при получении результатов: ${error.message}`);
    res.status(500).json({ error: "Internal server error" });
  }
});
app.post("/run-tests", authenticateJWT, async (req, res) => {
  const { labId, numberLab, userCode, selectedSubject } = req.body;

  if (!selectedSubject) {
    logger.error("Invalid input: selectedSubject is missing");
    return res.status(400).send("Invalid input");
  }

  logger.info(
    `Received request to run test script for subject: ${selectedSubject}`
  );

  let output = "";

  try {
    // Определяем, какой предмет выбран
    if (selectedSubject === "Предмет1") {
      // Логика для Предмет1
      if (!labId || !numberLab) {
        logger.error(
          "Invalid input: labId or numberLab is missing for Предмет1"
        );
        return res.status(400).send("Invalid input");
      }

      logger.info(
        `Running tests for Предмет1, labId: ${labId}, numberLab: ${numberLab}`
      );

      const testScriptPath = `./scripts/subject1/lab-${numberLab}.py`; // Путь к скрипту для Предмет1
      const pythonProcess = spawn("python", [testScriptPath, labId]);

      pythonProcess.stdout.on("data", (data) => {
        output += data.toString();
        logger.info(`stdout: ${data}`);
      });

      pythonProcess.stderr.on("data", (data) => {
        output += data.toString();
        logger.error(`stderr: ${data}`);
      });

      pythonProcess.on("close", async (code) => {
        logger.info(`child process exited with code ${code}`);
        await saveResult(req.user.username, numberLab, output, selectedSubject);
        res.status(200).json({ result: output });
      });

      pythonProcess.on("error", (err) => {
        logger.error(`Failed to start subprocess: ${err.message}`);
        res.status(500).send("Internal server error");
      });
    } else if (selectedSubject === "Предмет2") {
      // Логика для Предмет2
      if (!numberLab || !userCode) {
        logger.error(
          "Invalid input: numberLab or userCode is missing for Предмет2"
        );
        return res.status(400).send("Invalid input");
      }

      logger.info(`Running tests for Предмет2, numberLab: ${numberLab}`);

      // Сохраняем код пользователя в файл (если нужно)
      const userCodeFilePath = `./user_code/lab-${numberLab}.py`;
      fs.writeFileSync(userCodeFilePath, userCode);

      const testScriptPath = `./scripts/subject2/lab-${numberLab}.py`; // Путь к скрипту для Предмет2
      const pythonProcess = spawn("python", [testScriptPath, userCodeFilePath]);

      pythonProcess.stdout.on("data", (data) => {
        output += data.toString();
        logger.info(`stdout: ${data}`);
      });

      pythonProcess.stderr.on("data", (data) => {
        output += data.toString();
        logger.error(`stderr: ${data}`);
      });

      pythonProcess.on("close", async (code) => {
        logger.info(`child process exited with code ${code}`);
        await saveResult(req.user.username, numberLab, output, selectedSubject);
        res.status(200).json({ result: output });
      });

      pythonProcess.on("error", (err) => {
        logger.error(`Failed to start subprocess: ${err.message}`);
        res.status(500).send("Internal server error");
      }
    );
    } else {
      logger.error(`Unknown subject: ${selectedSubject}`);
      return res.status(400).send("Unknown subject");
    }
  } catch (error) {
    logger.error(`Error running tests: ${error.message}`);
    res.status(500).send("Internal server error");
  }
});

// Функция для сохранения результата в базу данных
async function saveResult(username, labNumber, result, subject) {
  try {
    // Создаем таблицу, если она не существует
    await query(`
      CREATE TABLE IF NOT EXISTS lab_results (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
        lab_number INTEGER NOT NULL,
        result TEXT NOT NULL,
        subject VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Сохраняем результат в базу данных
    await query(
      "INSERT INTO lab_results (username, lab_number, result, subject) VALUES ($1, $2, $3, $4)",
      [username, labNumber, result, subject]
    );
    logger.info(`Результат для предмета ${subject} сохранен в базу данных`);
  } catch (error) {
    logger.error(`Ошибка сохранения результата: ${error.message}`);
    throw error;
  }
}
// app.post("/run-tests", authenticateJWT, async (req, res) => {
//   const { labId, numberLab } = req.body;

//   if (!labId || !numberLab) {
//     logger.error("Invalid input: labId or numberLab is missing");
//     return res.status(400).send("Invalid input");
//   }

//   logger.info(
//     `Received request to run test script for lab ID: ${labId} and numberLab: ${numberLab}`
//   );

//   const testScriptPath = `./scripts/lab-${numberLab}.py`; // Укажите путь к вашему скрипту
//   const pythonProcess = spawn("python", [testScriptPath, labId]);

//   let output = "";

//   pythonProcess.stdout.on("data", (data) => {
//     output += data.toString();
//     logger.info(`stdout: ${data}`);
//   });

//   pythonProcess.stderr.on("data", (data) => {
//     output += data.toString();
//     logger.error(`stderr: ${data}`);
//   });

//   pythonProcess.on("close", async (code) => {
//     logger.info(`child process exited with code ${code}`);

//     try {
//       // Создаем таблицу, если она не существует
//       await query(`
//         CREATE TABLE IF NOT EXISTS lab_results (
//           id SERIAL PRIMARY KEY,
//           username VARCHAR(255) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
//           lab_number INTEGER NOT NULL,
//           result TEXT NOT NULL,
//           created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
//         )
//       `);

//       // Извлекаем username из токена JWT
//       const username = req.user.username; // Username из JWT
//       if (!username) {
//         logger.error("username is missing in JWT");
//         return res.status(400).send("username is missing in JWT");
//       }

//       logger.info(
//         `Saving result for username: ${username}, lab_number: ${numberLab}`
//       );

//       // Сохраняем результат в базу данных
//       await query(
//         "INSERT INTO lab_results (username, lab_number, result) VALUES ($1, $2, $3)",
//         [username, numberLab, output]
//       );
//       logger.info(
//         `Результат для лабораторной работы ${numberLab} сохранен в базу данных`
//       );
//       res.status(200).json({ result: output });
//     } catch (error) {
//       logger.error(
//         `Ошибка сохранения результата в базу данных: ${error.message}`
//       );
//       res.status(500).send("Internal server error");
//     }
//   });

//   pythonProcess.on("error", (err) => {
//     logger.error(`Failed to start subprocess: ${err.message}`);
//     res.status(500).send("Internal server error");
//   });
// });

const PORT =  3000;

const startServer = async () => {
  try {
    app.listen(PORT, () => {
      logger.info(`Server is running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Ошибка подключения к базе данных:", error.message);
  }
};

startServer();
