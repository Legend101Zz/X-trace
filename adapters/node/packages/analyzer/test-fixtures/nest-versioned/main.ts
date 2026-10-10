import { NestFactory, VersioningType } from "@nestjs/core";

async function bootstrap() {
  const app = await NestFactory.create({});
  app.enableVersioning({ type: VersioningType.URI });
  await app.listen(3000);
}
bootstrap();
