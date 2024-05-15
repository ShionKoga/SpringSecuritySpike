import {createContext, useContext} from 'react'
import User from './model/User.ts'

export const UserContext = createContext<User | null>(null)
export function useUser() {
    return useContext(UserContext)
}

export const SetUserContext = createContext<(newUser: User | null) => void>((_: User | null) => {})
export function useSetUser() {
    return useContext(SetUserContext)
}