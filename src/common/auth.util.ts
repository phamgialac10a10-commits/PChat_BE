export async function generateOTP() {
    const random = Math.floor(100000 + (Math.random() * 899999));
    
    return random;
}