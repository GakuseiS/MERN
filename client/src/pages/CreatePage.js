import React, { useState, useEffect, useContext } from 'react'
import { useHistory } from 'react-router'
import { AuthContext } from '../context/AuthContext'
import { useHttp } from '../hooks/http.hook'

export const CreatePage = () => {
    const history = useHistory()
    const auth = useContext(AuthContext)
    const [link, setLink] = useState('')
    const {request} = useHttp()

    useEffect(() => {
        window.M.updateTextFields() //активирует импуты
    }, [])

    const pressHandler = async (event) => {
        if(event.key === 'Enter') {
            try {
                const data = await request('/api/link/generate', 'POST', {from: link}, {
                    Authorization: `Bearer ${auth.token}`
                })
                history.push(`/detail/${data.link._id}`)
            } catch (e) {

            }
        }
    }
    return (
        <div className="row">
            <div className="col s8 offset-s2" style={{paddingTop: '2rem'}}>
                <div className="input-field">
                    <input placeholder="Вставьте ссылку" id="link" type="text" value={link} onChange={e => setLink(e.target.value)} onKeyPress={pressHandler}/>
                    <label htmlFor="link">Введилте ссылку</label>
                </div>
            </div>
        </div>
    )
}