import { Controller, Get, Version } from "@nestjs/common";

@Controller("items")
export class ItemsController {
  @Get()
  @Version("2")
  list() {
    return [];
  }
}
