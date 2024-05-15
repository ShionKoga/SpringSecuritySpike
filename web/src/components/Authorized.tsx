import {ReactElement} from 'react'
import {useUser} from '../UserContext.ts'


export default function Authorized(props: { children: ReactElement }) {
    const user = useUser()
    return (
        user && props.children
    )
}