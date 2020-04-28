import React, { useState } from 'react';
// material-ui
import Header from './components/Header/Header';
import TextField from '@material-ui/core/TextField';
import Container from '@material-ui/core/Container';
import Grid from '@material-ui/core/Grid';
import Button from '@material-ui/core/Button';
import OutlinedInput from '@material-ui/core/OutlinedInput';
import InputAdornment from '@material-ui/core/InputAdornment';
import FormHelperText from '@material-ui/core/FormHelperText';
import Typography from '@material-ui/core/Typography';

// algorithm
import rsa from './components/Algorithms/rsa';
// css
import './App.css';

function App() {
  //const [keys, setKeys ] = useState(); 
  const [n, setN] = useState('');
  const [q, setQ] = useState('');
  const [p, setP] = useState('');
  const [e, setE] = useState('');
  const [d, setD] = useState('');
  const [totient, setTotient] = useState('');
  const [plaintext, setPlainText] = useState('');
  const [size, setSize] = useState('')
  const [plaintext2, setPlainText2] = useState('');
  const [ciphertext, setCiphertext] =useState('');
  const [time, setTime] = useState('')

  const newKeys = (size) => {
    var t = -performance.now();
    const keys =  rsa.generate(size);
    setSize(size);
    setP(keys.p);
    setN(keys.n);
    setQ(keys.q);
    setE(keys.e);
    setD(keys.d);
    setTotient(keys.totient.toString(16));
    
    t += performance.now();
    setTime((t/1000).toFixed(3))
  }

  const encrypt =  () => {
    var encodeMsg = rsa.pkcs1pad2(plaintext, (size+7)>>3);
    setCiphertext(rsa.encrypt(encodeMsg, n, e));
    setPlainText2('')
  }

  const decrypt = () => {
    var decryptedMsg = rsa.decrypt(ciphertext, d, n)
    setPlainText2(rsa.pkcs1unpad2(decryptedMsg, (size+7)>>3))
  }

  return (
    <div className="App">
      <Header
        color="dark"
        routes="/"
        brand="RSA Cryptography Demo"
        fixed
        changeColorOnScroll={{
          height: 100,
          color: "rose"
        }}
      />

      <div className="grid">
        <Container>
          <Grid container spacing={2}>
          
            <Grid item xs={12}>
              <Grid container spacing={1}>
                <Grid item><Typography>Generate Key</Typography></Grid>
                <Grid item><Button onClick={() => newKeys(512)} variant="contained">512 bit</Button></Grid>
                <Grid item><Button onClick={() => newKeys(1024)} variant="contained">1024 bit</Button></Grid>
                <Grid item><Button onClick={() => newKeys(2048)} variant="contained">2048 bit</Button></Grid>
                <Grid item><Button onClick={() => newKeys(4096)} variant="contained">4096 bit</Button></Grid>
                <Grid item>
                  <OutlinedInput
                    id="outlined-adornment-weight"
                    value={time}
                    endAdornment={<InputAdornment position="end">sec</InputAdornment>}
                    aria-describedby="outlined-weight-helper-text"
                    labelWidth={0}
                  />
                  <FormHelperText id="outlined-weight-helper-text">Elapsed time</FormHelperText>
                </Grid>
              </Grid>
          
            </Grid>
          
            <Grid item xs={6}>
              <TextField
                id="outlined-multiline-static"
                label="P (hex)"
                fullWidth
                multiline
                value={rsa.linebrk(p.toString(16))}
                variant="outlined"
              />
            </Grid>
            <Grid item xs={6}>
            <TextField
                id="outlined-multiline-static"
                label="Q (hex)"
                fullWidth
                multiline
                value={rsa.linebrk(q.toString(16))}
                variant="outlined"
              />
            </Grid>
            <Grid item xs={6}>
            <TextField
                id="outlined-multiline-static"
                label="Modulus (hex)"
                fullWidth
                multiline
                value={rsa.linebrk(n.toString(16))}
                variant="outlined"
              />
              </Grid>
            <Grid item xs={6}>
              <TextField
                  id="outlined-multiline-static"
                  label="Public exponent (hex)"
                  fullWidth
                  multiline
                  value={rsa.linebrk(e.toString(16))}
                  variant="outlined"
                />
            </Grid>
            <Grid item xs={6}>
              <TextField
                  id="outlined-multiline-static"
                  label="Totient (hex)"
                  fullWidth
                  multiline
                  value={rsa.linebrk(totient.toString(16))}
                  variant="outlined"
                />
            </Grid>
            <Grid item xs={6}>
              <TextField
                  id="outlined-multiline-static"
                  label="Private exponent (hex)"
                  fullWidth
                  multiline
                  value={d.toString(16)}
                  variant="outlined"
                />
            </Grid>
          </Grid>
          <Grid container spacing={2} direction="row" justify="center" alignItems="center">
            <Grid item xs={4}>
              <TextField
                id="outlined-multiline-static"
                label="Plaintext"
                fullWidth
                multiline
                value={plaintext}
                variant="outlined"
                onChange={e => setPlainText(e.target.value)}
              />
            </Grid>
            <Grid item xs={4}>
              <Grid container alignItems="center" justify="center">
                <Button onClick={() => encrypt()} variant="contained">Encrypt</Button>
              </Grid>
            </Grid>
            <Grid item xs={4}>
              <TextField
                id="outlined-multiline-static"
                label="Ciphertext"
                fullWidth
                multiline
                value={rsa.linebrk(ciphertext.toString(16))}
                variant="outlined"
              />
            </Grid>
          </Grid>
          <Grid container spacing={2} direction="row" justify="center" alignItems="center">
            <Grid item xs={4}>
              <TextField
                id="outlined-multiline-static"
                label="Ciphertext"
                fullWidth
                multiline
                value={rsa.linebrk(ciphertext.toString(16))}
                variant="outlined"
              />
            </Grid>
            <Grid item xs={4}>
              <Grid container alignItems="center" justify="center">
                <Button onClick={() => decrypt()} variant="contained">Decrypt</Button>
              </Grid>
            </Grid>
            <Grid item xs={4}>
              <TextField
                id="outlined-multiline-static"
                label="Plaintext"
                fullWidth
                multiline
                value={plaintext2}
                variant="outlined"
              />
            </Grid>
          </Grid>          
        </Container>
      </div>
    </div>
  );
}

export default App;
