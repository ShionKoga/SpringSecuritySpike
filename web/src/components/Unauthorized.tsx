import {ReactElement} from 'react'
import {useUser} from '../UserContext.ts'


export default function Unauthorized(props: {children: ReactElement}) {
    const user = useUser()
    return (
        user === null && props.children
    )
}