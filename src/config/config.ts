import { registerAs } from '@nestjs/config';

export enum ConfigKeys {
  App = 'App',
  Db = 'Db',
  Jwt = 'Jwt',
}

const AppConfig = registerAs(ConfigKeys.App, () => ({ port: 3000 }));
const JwtConfig = registerAs(ConfigKeys.Jwt, () => ({
  accessTokenSecret: 'e7914779262af854b0a8680',
  refreshTokenSecret: 'ea182f99adeaa1d50659f04',
}));
const DbConfig = registerAs(ConfigKeys.Db, () => ({
  port: 5432,
  host: 'localhost',
  username: 'postgres',
  password: '6945',
  database: 'auth-otp',
}));

export const configurations = [AppConfig, DbConfig, JwtConfig];

// const AppConfig = registerAs(ConfigKeys.App, () => {
//   return {
//     port: 3000,
//   };
// });
