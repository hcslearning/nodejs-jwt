const main = async () => {
    // Test bcrypt
    const bcrypt        = require('bcryptjs')
    const plainPassword = 'MiContrasena123'
    const password      = await bcrypt.hash( plainPassword, 10 )
    const compare       = await bcrypt.compare(plainPassword, password)
    
    console.log(`Plain Password: ${plainPassword}`)
    console.log(`bcrypt.hash( plainpwd ): ${password}`)
    console.log(`bcrypt.compare( plainpwd, hash ): ${compare}`)

    // Test jsonwebtoken
    const jwt = require('jsonwebtoken')
    const token = '1234567890abcdefghijk'
    const payloadEncrypted = jwt.sign(
        {nombre: 'Chola', edad: 15},
        token,
        {expiresIn: "2h"}
    )
        
    console.dir( {payloadEncrypted} )
    const objDecrypted = jwt.verify(payloadEncrypted, token)
    console.dir({objDecrypted})

}

main()
