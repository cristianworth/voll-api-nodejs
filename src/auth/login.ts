import { type Request, type Response } from "express";
import jwt from "jsonwebtoken";
import { Autenticaveis } from "./authEntity.js";

import { AppDataSource } from "../data-source.js";
import { decryptPassword } from "../utils/senhaUtils.js";
import { AppError } from "../error/ErrorHandler.js";

export const login = async (req: Request, res: Response): Promise<void> => {
  const { email, senha } = req.body;

  const autenticavel = await AppDataSource.manager.findOne(Autenticaveis, {
    select: ["id", "rota", "role", "senha"],
    where: { email },
  });

  if (autenticavel == null) {
    throw new AppError("Não encontrado!", 404);
  } else {
    const { id, rota, role, senha: senhaAuth } = autenticavel;
    const senhaCorrespondente = decryptPassword(senhaAuth);

    if (senha !== senhaCorrespondente) {
      throw new AppError("Senha incorreta!", 401);
    }

    const token = signToken(id, role);
    res.status(200).json(token);
  }
};

function signToken(id: string, role: string) {
  interface TokenProps {
    id: string;
    role: string;
  }

  const payload: TokenProps = { id: id, role: role };
  const secretKey: string = process.env.SECRET || "";
  console.log("secretKey = ", secretKey);

  const token = jwt.sign(payload, secretKey, { expiresIn: "24h" });
  console.log("token generated = ", token);

  try {
    const decodedToken: TokenProps = jwt.verify(
      token,
      process.env.SECRET
    ) as TokenProps;
    console.log("Decoded Token:", decodedToken);

    const userId = decodedToken.id;
    
    // TODO: Esse decode não funciona no repositório https://github.com/cristianworth/voll-mobile
    // Como não é possivel decodificar o token, eu passo o userId já decodificado no retorno
    // Posteriormente terá que retornar somente o token codificado: return { token };
    return { token, userId };
  } catch (error) {
    console.error("Error decoding token:", error.message);
  }

  return { token };
}

export const logout = async (req: Request, res: Response): Promise<void> => {
  res.status(200).json({ auth: false, token: null });
};
