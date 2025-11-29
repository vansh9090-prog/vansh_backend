const { Telegraf } = require("telegraf");

// Your Bot Token
const bot = new Telegraf("8259780372:AAHwTmuhkr6eugiMsLVqTAqNnkCu5Ljddo4");

// When user sends any video → Bot replies with file_id
bot.on("video", async (ctx) => {
    const fileId = ctx.message.video.file_id;

    await ctx.reply(
        `🎬 Your Video File ID:\n\`${fileId}\``,
        { parse_mode: "Markdown" }
    );
});

// Start message
bot.start((ctx) => ctx.reply("Send me any video, I will give you its file_id."));

// Launch the bot
bot.launch()
    .then(() => console.log("Bot is running..."))
    .catch(console.error);