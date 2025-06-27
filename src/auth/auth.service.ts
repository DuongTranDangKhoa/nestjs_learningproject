import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
  // Hardcoded user credentials
  private readonly users = [
    {
      userId: 1,
      username: 'admin',
      password: '$2b$10$1lxfOkebE6ayXx/fTV7Y7.awQJzxKLl8ofxFO6TfejAard322TTde', // password: 12345
    },
  ];

  constructor(private jwtService: JwtService) {}

  async validateUser(username: string, password: string): Promise<any> {
    const user = this.users.find(user => user.username === username);
    if (user && await bcrypt.compare(password, user.password)) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async login(loginDto: LoginDto) {
    const user = await this.validateUser(loginDto.username, loginDto.password);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    
    const payload = { username: user.username, sub: user.userId };
    return {
      accessToken: this.jwtService.sign(payload),
      user: {
        id: user.userId,
        username: user.username,
      },
    };
  }
} 