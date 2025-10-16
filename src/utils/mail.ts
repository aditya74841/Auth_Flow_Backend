import Mailgen from "mailgen";
import nodemailer from "nodemailer";

interface optionsType {
  email: string;
  subject: string;
  mailgenContent: Mailgen.Content;
}

const sendEmail = async (options: optionsType) => {
  const mailGenerator = new Mailgen({
    theme: "default",
    product: {
      name: process.env.EMAIL_SENDER_NAME!,
      link: process.env.EMAIL_SENDER_LINK!,
    },
  });

  const emailTextual = mailGenerator.generatePlaintext(options.mailgenContent);

  const emailHtml = mailGenerator.generate(options.mailgenContent);

  const transporter = nodemailer.createTransport({
    service: "gmail",
    secure: true,
    port: 465,
    auth: {
      user: process.env.MAILTRAP_SMTP_USER!,
      pass: process.env.MAILTRAP_SMTP_PASS!,
    },
  });
  const mailOptions = {
    from: {
      name: process.env.EMAIL_SENDER_NAME!,
      address: process.env.MAILTRAP_SMTP_USER!,
    },
    to: options.email,
    subject: options.subject,
    text: emailTextual,
    html: emailHtml,
  };
  try {
    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.log(
      "Email service failed silently. Make sure you have provided your MAILTRAP credential in the .env file"
    );
    console.error("Error:", error);
  }
};
interface ForgotPasswordType {
  username: string | undefined;
  passwordResetUrl: string;
}

const forgotPasswordMailgenContent = ({
  username,
  passwordResetUrl,
}: ForgotPasswordType): Mailgen.Content => {
  return {
    body: {
      name: username,
      intro: "We received a request to reset the password for your account.",
      action: {
        instructions:
          "To reset your password, click the button below or use the following link:",
        button: {
          color: "#22BC66",
          text: "Reset Password",
          link: passwordResetUrl,
        },
      },
      outro:
        "Need help, or have questions? Just reply to this email — we'd love to help.",
    },
  };
};

interface EmailVerificationType {
  username: string | undefined;
  verificationUrl: string;
}

/**
 *
 * @param {string} username
 * @param {string} verificationUrl
 * @returns {Mailgen.Content}
 * @description It designs the email verification mail
 */
const emailVerificationMailgenContent = ({
  username,
  verificationUrl,
}: EmailVerificationType): Mailgen.Content => {
  return {
    body: {
      name: username,
      intro: "Welcome to our app! We're very excited to have you on board.",
      action: {
        instructions:
          "To verify your email please click on the following button:",
        button: {
          color: "#22BC66", // Optional action button color
          text: "Verify your email",
          link: verificationUrl,
        },
      },
      outro:
        "Need help, or have questions? Just reply to this email, we'd love to help.",
    },
  };
};

export {
  sendEmail,
  forgotPasswordMailgenContent,
  emailVerificationMailgenContent,
};
