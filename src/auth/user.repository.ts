import { ConflictException } from "@nestjs/common";
import { EntityRepository, Repository } from "typeorm"
import { AuthCredentialsDto } from "./dto/auth-credentials.dto";
import { User } from "./user.entity";
import * as bcrypt from 'bcrypt';

@EntityRepository(User)
export class UserRepository extends Repository<User> {
    async singUp(authCredentialsDto: AuthCredentialsDto): Promise<void> {
        const { username, password } = authCredentialsDto;
        const salt = await bcrypt.genSalt();

        const user = new User();
        user.username = username;
        user.salt = salt;
        user.password = await this.hashPass(password, salt);

        try {
            await user.save();
        } catch (error) {
            throw new ConflictException(error);
        }
        
    }

    async validatePassword(authCredentialsDto: AuthCredentialsDto): Promise<string>  {
        const { username, password } = authCredentialsDto;
        const user = await this.findOne({username}); 

        if(user && await user.validatePassword(password)) return user.username;
        
        return null
    }

    private async hashPass(pass: string, salt: string): Promise<string> {
        return bcrypt.hash(pass, salt);
    }

}