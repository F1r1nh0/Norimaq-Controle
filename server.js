import express from "express";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
import cron from "node-cron";
import dayjs from "dayjs";
import process from "process";

dotenv.config();
const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);
// Configuração de CORS
app.use(
  cors({
    origin: [
      "http://localhost:3000", // local
      "https://controle-norimaq.vercel.app", // Produção
      "https://dev-controle-norimaq.vercel.app", // Dev
    ],
    methods: ["GET", "POST", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true, // importante se for usar cookies
  })
);

console.log("Supabase URL:", process.env.SUPABASE_URL);
console.log("Supabase KEY:", process.env.SUPABASE_KEY ? " set" : " missing");
console.log("JWT SECRET:", process.env.JWT_SECRET ? " set" : " missing");

// Middleware de autenticação
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token não fornecido" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({ error: "Token expirado" });
      }
      return res.status(403).json({ error: "Token inválido" });
    }
    req.user = user;
    next();
  });
}
// Login
app.post("/login", async (req, res) => {
  const { username, password, selectedRole } = req.body; // <- adicionamos selectedRole

  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("username", username)
      .single();

    if (error || !user) {
      return res.status(400).json({ error: "Credenciais inválidas" });
    }

    if (password !== user.password) {
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    // Verifica se o setor escolhido confere com o setor do usuário no banco
    if (selectedRole && selectedRole !== user.role) {
      return res.status(403).json({
        error: "Credenciais inválidas",
      });
    }

    // Access token - expira rápido
    const accessToken = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    // Refresh token - expira mais lento
    const refreshToken = jwt.sign(
      { id: user.id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "7d" }
    );

    // Salva refresh token no banco
    await supabase.from("users").update({ refreshToken }).eq("id", user.id);

    res.json({
      accessToken,
      refreshToken,
      role: user.role,
      role_id: user.sector_id,
    });
  } catch (err) {
    console.error("Erro inesperado no login:", err.message);
    res.status(500).json({ error: "Erro interno no servidor" });
  }
});

// Rota para renovar token
app.post("/refresh", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken)
    return res.status(401).json({ error: "Refresh token não fornecido" });

  // Verifica se o refresh token existe no banco
  const { data: user } = await supabase
    .from("users")
    .select("*")
    .eq("refreshToken", refreshToken)
    .single();

  if (!user) return res.status(403).json({ error: "Refresh token inválido" });

  jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err) => {
    if (err)
      return res
        .status(403)
        .json({ error: "Refresh token inválido ou expirado" });

    // Gera novo access token
    const newAccessToken = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ accessToken: newAccessToken });
  });
});

// Verifica se o token é válido
app.get("/auth", authenticateToken, (req, res) => {
  res.json({
    valid: true,
    user: req.user, // { id, role }
  });
});

// Logout → remove refresh token
app.post("/logout", async (req, res) => {
  const { refreshToken } = req.body;
  await supabase
    .from("users")
    .update({ refreshToken: null })
    .eq("refreshToken", refreshToken);

  res.json({ message: "Logout realizado com sucesso" });
});

// Criar OS (apenas PCP)
app.post("/os", authenticateToken, async (req, res) => {
  if (req.user.role !== "PCP")
    return res.status(403).json({ error: "Acesso negado" });

  const {
    orderNumber,
    partName,
    partNumber,
    quantity,
    note,
    createdAt,
    status,
    priority,
    currentSector,
    routing,
    progressDetails,
  } = req.body;

  const { error } = await supabase.from("Ordens_Servico").insert([
    {
      orderNumber,
      partName,
      partNumber,
      quantity,
      note,
      createdAt,
      status,
      priority,
      currentSector,
      routing,
      progressDetails,
    },
  ]);

  if (error) return res.status(500).json({ error: error.message });

  res.json({ message: "OS criada com sucesso" });
});

// Editar OS (PATCH)
app.patch("/os/:orderNumber", authenticateToken, async (req, res) => {
  const { orderNumber } = req.params;
  const updates = req.body;

  // Qualquer usuário autenticado pode editar
  const { data, error } = await supabase
    .from("Ordens_Servico")
    .update(updates)
    .eq("orderNumber", orderNumber)
    .select("*") // retorna os campos atualizados
    .single();

  if (error) return res.status(500).json({ error: error.message });

  return res.json({
    message: `OS atualizada com sucesso (${req.user.role})`,
    updatedOS: data, // retorna a OS editada
  });
});

// Deletar OS (apenas PCP)
app.delete("/os/:orderNumber", authenticateToken, async (req, res) => {
  if (req.user.role !== "PCP") {
    return res.status(403).json({ error: "Apenas o PCP pode excluir uma OS" });
  }

  const { orderNumber } = req.params;

  const { error } = await supabase
    .from("Ordens_Servico")
    .delete()
    .eq("orderNumber", orderNumber);

  if (error) return res.status(500).json({ error: error.message });

  res.json({ message: `OS ${orderNumber} excluída com sucesso` });
});

// PCP finaliza OS (retirar)
app.patch("/os/:orderNumber/finalizar", authenticateToken, async (req, res) => {
  if (req.user.role !== "PCP")
    return res.status(403).json({ error: "Acesso negado" });

  const { orderNumber } = req.params;

  await supabase
    .from("Ordens_Servico")
    .update({ status: "Finalizado" })
    .eq("orderNumber", orderNumber);

  res.json({ message: "OS finalizada com sucesso" });
});

// Listar todas as OS (somente PCP)
app.get("/os", authenticateToken, async (req, res) => {
  if (
    req.user.role !== "PCP" &&
    req.user.role !== "ALMOXARIFADO" &&
    req.user.role !== "ADMIN"
  ) {
    return res.status(403).json({ error: "Acesso negado" });
  }

  const { data, error } = await supabase.from("Ordens_Servico").select("*");

  if (error) return res.status(500).json({ error: error.message });

  res.json(data);
});


/*/ esse n presta mas to testando
// Listar OS do setor correspondente ao usuário logado
app.get("/os/setor", authenticateToken, async (req, res) => {
  const setor = req.user.role;

  try {
    const { data, error } = await supabase.from("Ordens_Servico").select("*");
    if (error) return res.status(500).json({ error: error.message });

    const filtradas = data.filter((os) => {
      const setorAtual =
        os.currentSector?.sector === setor || os.currentSector === setor;

      // Verifica se o setor logado existe no roteiro da OS
      const passouPorRoteiro =
        Array.isArray(os.routing) && os.routing.some((r) => r.sector === setor);

      const finalizada = os.status?.toLowerCase() === "finalizado";

      // se o setor for MONTAGEM
      if (setor?.toUpperCase() === "MONTAGEM") {
        const setoresPermitidos = ["ELETRICA", "MECANICA", "TESTE", "MONTAGEM"];
        return (
          setoresPermitidos.includes(
            os.currentSector?.sector?.toUpperCase?.()
          ) ||
          setoresPermitidos.includes(os.currentSector?.toUpperCase?.()) ||
          (finalizada &&
            Array.isArray(os.routing) &&
            os.routing.some((r) =>
              setoresPermitidos.includes(r.sector?.toUpperCase?.())
            ))
        );
      }

      // Comportamento padrão para os demais setores
      return setorAtual || (finalizada && passouPorRoteiro);
    });

    res.json(filtradas);
  } catch (err) {
    console.error("Erro ao listar OS por setor:", err.message);
    res.status(500).json({ error: "Erro interno ao listar OS" });
  }
}); /*/

//Listar OS do setor correspondente ao usuário logado
app.get("/os/setor", authenticateToken, async (req, res) => {
  const setor = req.user.role;
  
  // Paginação
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const start = (page - 1) * limit;
  const end = start + limit - 1;
  

  try {
    const { data, error } = await supabase.from("Ordens_Servico").select("*");
    
    if (error) return res.status(500).json({ error: error.message });

    const filtradas = data.filter((os) => {
      const finalizada = os.status?.toLowerCase() === "finalizado";
      
        // se o setor for MONTAGEM
      if (setor?.toUpperCase() === "MONTAGEM") {
        const setoresPermitidos = ["ELETRICA", "MECANICA", "TESTE", "MONTAGEM"];
        return (
          setoresPermitidos.includes(
            os.currentSector?.sector?.toUpperCase?.()
          ) ||
          setoresPermitidos.includes(os.currentSector?.toUpperCase?.()) ||
          (finalizada &&
            Array.isArray(os.routing) &&
            os.routing.some((r) =>
              setoresPermitidos.includes(r.sector?.toUpperCase?.())
            ))
        );
      }
      
      const setorAtual =
        os.currentSector?.sector === setor || os.currentSector === setor;

      // Verifica se o setor logado existe no roteiro da OS
      const passouPorRoteiro =
        Array.isArray(os.routing) && os.routing.some((r) => r.sector === setor);

      // Mostra se está no setor ou se está finalizada mas passou pelo roteiro
      return setorAtual || (finalizada && passouPorRoteiro);
      
    });
    
       // Paginação manual
    const total = filtradas.length;
    const paginadas = filtradas.slice(start, end + 1);

    res.json(
      page,
      total,
      totalPages: Math.ceil(total / limit),
      data: paginadas,
    });
  } catch (err) {
    console.error("Erro ao listar OS por setor:", err.message);
    res.status(500).json({ error: "Erro interno ao listar OS" });
  }
});

// Buscar OS específica pelo orderNumber
app.get("/os/:orderNumber/ler", authenticateToken, async (req, res) => {
  const orderNumber = req.params.orderNumber;
  const setorUsuario = req.user.role?.toUpperCase();

  try {
    const { data: os, error } = await supabase
      .from("Ordens_Servico")
      .select("*")
      .eq("orderNumber", orderNumber)
      .single();

    if (error || !os) {
      return res.status(404).json({ error: "OS não encontrada" });
    }

    // Se for PCP ou ALMOXARIFADO e ADMIN, pode ver tudo
    if (["PCP", "ALMOXARIFADO" , "ADMIN"].includes(setorUsuario)) {
      return res.json(os);
    }

    // Verifica se o setor do usuário está no roteiro
    const roteiro = Array.isArray(os.routing) ? os.routing : [];
    const indexSetorUsuario = roteiro.findIndex(
      (r) => r.sector?.toUpperCase() === setorUsuario
    );

    //se for MONTAGEM, pode ver também ELETRICA, MECANICA e TESTE
    if (setorUsuario === "MONTAGEM") {
      const setoresPermitidos = ["ELETRICA", "MECANICA", "TESTE", "MONTAGEM"];
      const setorAtual =
        os.currentSector?.sector?.toUpperCase?.() ||
        os.currentSector?.toUpperCase?.();

      if (setoresPermitidos.includes(setorAtual)) {
        return res.json(os);
      }
    }

    if (indexSetorUsuario === -1) {
      // Setor não está no roteiro
      return res.status(403).json({
        error: "Seu setor não faz parte do roteiro desta OS.",
      });
    }

    // Se chegou até aqui, tudo ok
    return res.json(os);
  } catch (err) {
    console.error("Erro ao buscar OS:", err.message);
    res.status(500).json({ error: "Erro interno ao buscar OS." });
  }
});

// Setor registra produção
app.patch("/os/:orderNumber/producao", authenticateToken, async (req, res) => {
  const { orderNumber } = req.params;
  const { producedQuantity, defectiveQuantity, operatorName } = req.body;

  // PCP não pode registrar
  if (req.user.role === "PCP") {
    return res
      .status(403)
      .json({ error: "PCP não deve registrar produção, apenas validar" });
  }

  if (!operatorName) {
    return res.status(400).json({ error: "Nome do operador é obrigatório" });
  }

  const { data: os, error } = await supabase
    .from("Ordens_Servico")
    .select("*")
    .eq("orderNumber", orderNumber)
    .single();

  if (error || !os) return res.status(404).json({ error: "OS não encontrada" });

  const atualizacoes = {
    currentQuantity: producedQuantity,
    defectiveQuantity,
    operatorName, // <-- registrando o operador
    status: "Aguardando verificação PCP",
    pendingSector: req.user.role,
  };

  const { data: updated, error: updateError } = await supabase
    .from("Ordens_Servico")
    .update(atualizacoes)
    .eq("orderNumber", orderNumber)
    .select("*")
    .single();

  if (updateError) return res.status(500).json({ error: updateError.message });

  res.json({
    message: `Produção registrada por ${req.user.role} (${operatorName}). Aguardando PCP.`,
    os: updated,
  });
});
// PCP valida produção e libera próximo setor
app.patch("/os/:orderNumber/validar", authenticateToken, async (req, res) => {
  if (req.user.role !== "PCP") {
    return res
      .status(403)
      .json({ error: "Apenas o PCP pode validar a produção" });
  }

  const { orderNumber } = req.params;
  const { aprovado } = req.body; // true ou false

  const { data: os, error } = await supabase
    .from("Ordens_Servico")
    .select("*")
    .eq("orderNumber", orderNumber)
    .single();

  if (error || !os) return res.status(404).json({ error: "OS não encontrada" });

  if (os.status !== "Aguardando verificação PCP") {
    return res
      .status(400)
      .json({ error: "Não há produção pendente para validar" });
  }

  let atualizacoes = {};

  if (aprovado) {
    // Descobre o próximo setor no roteiro
    const rota = os.routing;
    const indexAtual = rota.findIndex((r) => r.sector === os.pendingSector);
    const proximo = rota[indexAtual + 1];

    atualizacoes = {
      status: proximo ? "Em andamento" : "Finalizado",
      currentSector: proximo || null,
      pendingSector: null,
    };
  } else {
    atualizacoes = {
      status: "Reprovado pelo PCP",
    };
  }

  const { data: updated, error: updateError } = await supabase
    .from("Ordens_Servico")
    .update(atualizacoes)
    .eq("orderNumber", orderNumber)
    .select("*")
    .single();

  if (updateError) return res.status(500).json({ error: updateError.message });

  res.json({
    message: `Produção validada pelo PCP. ${
      aprovado ? "Avançando para próximo setor" : "Reprovada"
    }.`,
    os: updated,
  });
});

// Todos os logs
app.get("/log", authenticateToken, async (req, res) => {
  const { data, error } = await supabase
    .from("Log_OS")
    .select("*")
    .order("date", { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Logs de uma OS específica
app.get("/log/:orderNumber", authenticateToken, async (req, res) => {
  const { orderNumber } = req.params;
  const { data, error } = await supabase
    .from("Log_OS")
    .select("*")
    .eq("orderNumber", orderNumber)
    .order("date", { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Criar um log (qualquer setor pode registrar uma ação)
app.post("/log", authenticateToken, async (req, res) => {
  const { sector, description, date, orderNumber } = req.body;

  if (!sector || !description || !date || orderNumber === undefined) {
    return res.status(400).json({ error: "Todos os campos são obrigatórios" });
  }

  const { data, error } = await supabase
    .from("Log_OS")
    .insert([{ sector, description, date, orderNumber }])
    .select();

  if (error) {
    console.error("Erro ao inserir log:", error);
    return res.status(500).json({ error: error.message });
  }

  res.json({ message: "Log registrado com sucesso", log: data[0] });
});

// Deletar um log pelo ID
app.delete("/log/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;

  const { error } = await supabase.from("Log_OS").delete().eq("id", id);

  if (error) {
    console.error("Erro ao deletar log:", error);
    return res.status(500).json({ error: error.message });
  }

  res.json({ message: `Log ${id} deletado com sucesso` });
});

// Atualizar orderNumber nos log
app.patch("/log/:orderNumber", authenticateToken, async (req, res) => {
  const { orderNumber } = req.params; // orderNumber antigo
  const { orderNumber: newOrderNumber } = req.body; // orderNumber novo

  // Se veio string vazia → erro
  if (newOrderNumber === "") {
    return res.status(400).json({ error: "orderNumber não pode ser vazio" });
  }

  // Se não veio nada no body erro
  if (newOrderNumber === undefined) {
    return res.status(400).json({ error: "Novo orderNumber é obrigatório" });
  }

  // Se veio null permite atualizar para null
  const { data, error } = await supabase
    .from("Log_OS")
    .update({ orderNumber: newOrderNumber })
    .eq("orderNumber", orderNumber)
    .select("*");

  if (error) return res.status(500).json({ error: error.message });

  res.json({
    message: "Logs atualizados com sucesso",
    updatedLogs: data,
  });
});

//Pausa todas as OS em produção às 17h
cron.schedule("* 20 * * *", async () => {
  console.log("Executando pausa automática de OS em produção...");

  try {
    //Buscar todas as OS que estão em produção
    const { data: osEmProducao, error: erroBusca } = await supabase
      .from("Ordens_Servico")
      .select("*")
      .eq("status", "Em produção");

    if (erroBusca) throw new Error(erroBusca.message);

    if (!osEmProducao || osEmProducao.length === 0) {
      console.log("Nenhuma OS em produção no momento.");
      return;
    }

    //Pausar todas
    const { data: pausadas, error: erroPausa } = await supabase
      .from("Ordens_Servico")
      .update({ status: "Pausada" })
      .eq("status", "Em produção")
      .select("*");

    if (erroPausa) throw new Error(erroPausa.message);

    console.log(`${pausadas.length} OS pausadas automaticamente.`);

    //Inserir log para cada OS pausada
    const agora = dayjs().format("YYYY-MM-DD HH:mm:ss");

    const logs = pausadas.map((os) => ({
      orderNumber: os.orderNumber,
      sector: "Sistema",
      description: `Produção pausada automaticamente às 17h`,
      date: new Date().getTime(),
    }));

    const { error: erroLog } = await supabase.from("Log_OS").insert(logs);

    if (erroLog) {
      console.error("Erro ao registrar logs:", erroLog.message);
    } else {
      console.log("Logs de pausa registrados com sucesso.");
    }
  } catch (err) {
    console.error("Erro no cron de pausa automática:", err.message);
  }
});

app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
