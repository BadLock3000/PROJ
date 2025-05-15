import { Box, Stack, styled, Typography } from "@mui/material";
import { Link } from "react-router-dom";

export default function Header({
  setIsAuthenticated,
  isAuthenticated,
  name,
  selectedSubject,
  setSelectedSubject,
}) { 
  console.log("aoaoaoaoa");
  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("name"); // Удаляем токен из localStorage
    setIsAuthenticated(false); // Сбрасываем состояние аутентификации
    setSelectedSubject(null);
  };

  return (
    <Stack
      direction="row"
      height="80px"
      width="100%"
      bgcolor="#1976d2"
      position="relative"
      overflow="hidden"
    >
      <Stack
        p={4}
        direction="row"
        justifyContent="space-between"
        alignItems="center"
        width="100%"
      >
        <Typography variant="h6" color="white">
         localhost проверки лабораторных работ
        </Typography>

        {selectedSubject && (
          <Typography variant="h6" color="white">
            {selectedSubject}
          </Typography>
        )}

        <Stack direction="row" gap={2}>
          {isAuthenticated && (
            <Typography variant="body1" color="white">
              {name}
            </Typography>
          )}
          {isAuthenticated ? (
            <Link
              to="/"
              onClick={handleLogout}
              style={{ textDecoration: "none", color: "white" }}
            >
              <Typography variant="body1">Выход</Typography>
            </Link>
          ) : (
            <Link
              to="/login"
              style={{ textDecoration: "none", color: "white" }}
            >
              <Typography variant="body1">Вход</Typography>
            </Link>
          )}
        </Stack>
      </Stack>
    </Stack>
  );
}
