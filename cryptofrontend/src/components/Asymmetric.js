import * as React from 'react';
import Form from '@mui/material/Box';
import TextField from '@mui/material/TextField';
import { Button, Container, Paper } from '@mui/material';

export default function Asymmetric() {

    const paperStyle={padding:'50px 20px', width:500, margin:'20px auto'}
    const fieldStyle={margin:'5px auto'}
    const[plainText, setPlainText]=React.useState('')
    const[password, setPassword]=React.useState('')

    const handleClick=(e)=>{
        e.preventDefault()
        const formInput={plainText, password}
        console.log(formInput)
        fetch(
            "http://localhost:8080/asy/c-t", 
            {
                method:'POST', 
                headers:{"Content-Type":"application/json"},
                body:JSON.stringify(formInput)
            }).then(()=>{
                console.log("data sent")
            })
    }

  return (

    <Container>
        <Paper elevation={3} style={paperStyle}>
            <h3>Asymmetic Cryptography</h3>
            <Form noValidate autoComplete="off">
            <TextField id="outlined-basic" label="Text to cipher" variant="outlined" style={fieldStyle} fullWidth 
                value={plainText} onChange={(e)=>setPlainText(e.target.value)}/>

            <TextField id="outlined-basic" label="Password" variant="outlined" style={fieldStyle} fullWidth
                value={password} onChange={(e)=>setPassword(e.target.value)}/>

            <Button variant="contained" style={fieldStyle} onClick={handleClick}>Execute Cryption</Button>
            </Form>

            {plainText}
            {password}
        </Paper>
    </Container>

  );
}
