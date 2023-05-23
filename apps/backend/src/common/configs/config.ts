import type { Config } from './config.interface';

const config: Config = {
  nest: {
    port: 8000,
  },
  cors: {
    enabled: true,
  },
  swagger: {
    enabled: true,
    title: 'Olorin',
    description: 'The Olorin API description',
    version: '1.5',
    path: 'api',
  },
  graphql: {
    playgroundEnabled: true,
    debug: true,
    schemaDestination: './src/schema.graphql',
    sortSchema: true,
  },
  security: {
    expiresIn: '2m',
    refreshIn: '7d',
    bcryptSaltOrRound: 10,
  },
};

export default (): Config => config;
