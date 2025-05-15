import ldap from "ldapjs";

const client = ldap.createClient({
  url: "ldaps://sipc.miet.ru:636",
  tlsOptions: {
    rejectUnauthorized: false, // Отключение проверки сертификатов
  },
});

export default client;
