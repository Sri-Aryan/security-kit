import { Controller, Get, Post, Param, UseGuards } from '@nestjs/common';
@Controller('orders')
export class OrdersController {
  @Get()
  findAll() { return []; }

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  findOne(@Param('id') id: string) { return id; }

  @Public()
  @Post('webhook')
  async webhook() {}
}
