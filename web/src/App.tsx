import {DefaultAuthRepository} from './repository/AuthRepository.ts'
import UserProvider from './components/UserProvider.tsx'
import Authorized from './components/Authorized.tsx'
import Unauthorized from './components/Unauthorized.tsx'
import LoginScreen from './screen/LoginScreen.tsx'
import MainScreen from './screen/MainScreen.tsx'

const authRepository = new DefaultAuthRepository()

export default function App() {
    return (
        <UserProvider authRepository={authRepository}>
            <Authorized>
                <MainScreen authRepository={authRepository}/>
            </Authorized>
            <Unauthorized>
                <LoginScreen authRepository={authRepository}/>
            </Unauthorized>
        </UserProvider>
    )
}

