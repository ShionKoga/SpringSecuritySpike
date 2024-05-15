import {useSetUser, useUser} from '../UserContext.ts'
import AuthRepository from '../repository/AuthRepository.ts'

export default function MainScreen(
    props: {authRepository: AuthRepository}
) {
    const user = useUser()
    const setUser = useSetUser()

    const onClickLogout = async () => {
        setUser(null)
        await props.authRepository.logout()
    }

    return (
        <>
            <div>main screen contents</div>
            <div>{`ログインユーザー名: ${user?.username}`}</div>
            <button onClick={onClickLogout}>ログアウト</button>
        </>
    )
}