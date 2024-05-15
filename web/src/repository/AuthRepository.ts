import User from '../model/User.ts'

export default interface AuthRepository {
    getUser(): Promise<User>
    login(username: string, password: string): Promise<void>
    signUp(username: string, password: string): Promise<void>
    logout(): Promise<void>
}

export class DefaultAuthRepository implements AuthRepository {
    async getUser(): Promise<User> {
        const url = '/api/auth/user'
        const res = await fetch(url)
        return await res.json()
    }

    async login(username: string, password: string): Promise<void> {
        const url = '/api/auth/login'
        const body = JSON.stringify({username, password})
        const headers = {'Content-Type': 'application/json'}
        await fetch(url, {method: 'POST', body, headers})
    }

    async signUp(username: string, password: string): Promise<void> {
        const url = '/api/auth/signup'
        const body = JSON.stringify({username, password})
        const headers = {'Content-Type': 'application/json'}
        await fetch(url, {method: 'POST', body, headers})
    }

    async logout(): Promise<void> {
        const url = '/api/auth/logout'
        await fetch(url)
    }
}