import {useState} from 'react'
import AuthRepository from '../repository/AuthRepository.ts'
import {useSetUser} from '../UserContext.ts'

export default function LoginScreen(
    props: { authRepository: AuthRepository }
) {
    const [username, setUsername] = useState('')
    const [password, setPassword] = useState('')
    const [userAlreadyHasAnAccount, setUserAlreadyHasAnAccount] = useState(true)
    const setUser = useSetUser()

    const onClickLogin = async () => {
        await props.authRepository.login(username, password)
        const user = await props.authRepository.getUser()
        setUser(user)
    }

    const onClickSignUp = async () => {
        await props.authRepository.signUp(username, password)
        const user = await props.authRepository.getUser()
        setUser(user)
    }

    return (
        <>
            <h1>ログイン</h1>
            <label>
                ユーザー名
                <input type="text" value={username} onChange={(e) => setUsername(e.target.value)}/>
            </label>
            <label>
                パスワード
                <input type="text" value={password} onChange={(e) => setPassword(e.target.value)}/>
            </label>
            {userAlreadyHasAnAccount
                ? <button onClick={onClickLogin}>ログイン</button>
                : <button onClick={onClickSignUp}>サインアップ</button>
            }
            {userAlreadyHasAnAccount
                ? <div>アカウントをお持ちでない場合は
                    <button onClick={() => setUserAlreadyHasAnAccount(false)}>こちら</button>
                </div>
                : <div>アカウントをお持ちの方は
                    <button onClick={() => setUserAlreadyHasAnAccount(true)}>こちら</button>
                </div>
            }
            <div>または<a href="/api/auth/login/google">Googleでサインイン</a></div>
            <div>または<a href="/api/auth/login/apple">Appleでサインイン</a></div>
        </>
    )
}