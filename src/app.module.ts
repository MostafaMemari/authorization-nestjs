import { Module } from '@nestjs/common';
import { CustomConfigsModule } from './modules/config/configs.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { TypeOrmDbConfig } from './config/typeorm.config';

@Module({
  imports: [
    CustomConfigsModule,
    TypeOrmModule.forRootAsync({
      useClass: TypeOrmDbConfig,
      inject: [TypeOrmDbConfig],
    }),
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
