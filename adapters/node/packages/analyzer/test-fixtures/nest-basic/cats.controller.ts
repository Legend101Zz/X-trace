import { All, Controller, Get, Post } from '@nestjs/common';

@Controller('cats')
export class CatsController {
  @Get()
  findAll() {}

  @Get(':id')
  findOne() {}

  @Post()
  create() {}

  @Get(['a', 'b'])
  both() {}
}

@Controller({ path: 'dogs' })
class DogsController {
  @All('bark')
  any() {}
}

class NotAController {
  @Get('nope')
  nope() {}
}
