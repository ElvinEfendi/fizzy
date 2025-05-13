class Command::ChatQuery < Command
  store_accessor :data, :query, :params

  def title
    "Chat query '#{query}'"
  end

  def execute
    response = chat.ask query
    Rails.logger.info "*** Commands: #{response.content}"
    generated_commands = replace_names_with_ids(JSON.parse(response.content))
    build_chat_response_with generated_commands
  end

  private
    def chat
      chat = RubyLLM.chat
      chat.with_instructions(prompt)
    end

    # TODO:
    #   - Don't generate initial /search if not requested. "Assign to JZ" should
    def prompt
      <<~PROMPT
        You are Fizzy’s command translator. Read the user’s request, consult the current view, and output 
        a **single JSON array** of command objects. Return nothing except that JSON.

        Fizzy data includes cards and comments contained in those. A card can represent an issue, a feature,
        a bug, a task, etc.
 
        ## Current context:

        The user is currently #{context.viewing_card_contents? ? 'inside a card' : 'viewing a list of cards' }.

        ## Supported commands:

        - Assign users to cards: Syntax: /assign [user]. Example: "/assign kevin"
        - Close cards: Syntax: /close [optional reason]. Example: "/close" or "/close not now"
        - Tag cards: Syntax: /tag [tag-name]. Example: "/tag performance"
        - Clear filters: Syntax: /clear
        - Get insight about cards: Syntax: /insight [query]. Example: "/insight summarize performance issues".
        - Search cards based on certain keywords: Syntax: /search. It supports the following parameters:
          * assignment_status: only used to filter unassigned cards with "unassigned".
          * terms: a list of terms to search for. Use this option to refine searches based on further keyword*based
             queries. Use the plural terms even when it's only one term. Always send individual terms separated by spaces.
             E.g: ["some", "term"] instead of ["some term"].
          * indexed_by: can be "newest", "oldest", "latest", "stalled", "closed"
          * engagement_status: can be "considering" or "doing". This refers to whether the team is working on something.
          * card_ids: a list of card ids
          * assignee_ids: a list of assignee names
          * creator_id: the name of a person
          * collection_ids: a list of collection names. Cards are contained in collections. Don't use unless mentioning
              specific collections.
          * tag_ids: a list of tag names.

        ## How to translate requests into commands

        1. Determine if you have the right context based on the "current context":
          - If it is is "inside a card", assume you are in the right context.
          - If it is "viewing a list of cards":
            a) consider emitting a /search command to filter the cards.
            b) consider emitting also a /insight command to refine context if needed. Don't do this when just asking for certain
            terms, only when the request justifies it. Pass the original query verbatim
            to insight as the [query]. If the query is "why is it taking so long?", add "/insight why is it taking so long?".

        2. Create the sequence of commands to satisfy the user's request.
          - If the request is about answering some question about cards, add an /insight command. You can only
            add ONE /insight command in total.
          - If it is "viewing a list of cards", before emitting the /insight command, consider emitting a /search command
            to create the right context to extract the insight from.
          - If the request requires acting on cards, add the sequence of commands that satisfy those. You can combine
            all of them except /search and /insight, which have an special consideration.

       ## How to filter cards

       - Find cards closed by someone with: (1) /search with indexed_by=closed and assignee_id=someone".
       - When asking for assigned cards, use assignee_ids not assignment_status.
       - If it's not clear what the user is asking for, perform a /search passing the original query as terms. E.g: for
         "red car" add { command: "/search", terms: ["red", "car"] }. 

       ## JSON format

        Each command will be a JSON object like. All the commands JSON objects a "command" key with the command.

        { command: "/close" }

        The "/search"" command can contain additional keys for the params in the JSON:

        { command: "/search", indexed_by: "closed", collection_ids: [ "Writebook", "Design" ] }

        The rest of commands will only have a "command" key, nothing else.

        The output will be a single list of JSON objects. Make sure to place values in double quotes and
        that you generate valid JSON. Always respond with a list like [ { }, { }, ...]

        # Other

        * Avoid empty preambles like "Based on the provided cards". Be friendly, favor an active voice.
        * Be concise and direct.
        * When emitting search commands, if searching for terms, remove generic ones.
        * The response can't contain more than one /search command.
        * The response can't contain more than one /insight command.
        * An unassigned card is a card without assignees.
        * Never create a /search or /insight without additional params.
        * An unassigned card can be closed or not. "unassigned" and "closed" are different unrelated concepts.
        * Only use assignment_status asking for unassigned cards. Never use in other circumstances.
        * There are similar commands to filter and act on cards (e.g: filter by assignee or assign 
          cards). Favor filtering/queries for commands like "cards assigned to someone".
      PROMPT
    end

    def replace_names_with_ids(commands)
      commands.each do |command|
        if command["command"] == "/search"
          command["assignee_ids"] = command["assignee_ids"]&.filter_map { |name| assignee_from(name)&.id }
          command["creator_id"] = assignee_from(command["creator_id"])&.id if command["creator_id"]
          command["collection_ids"] = command["collection_ids"]&.filter_map { |name| Collection.where("lower(name) = ?", name.downcase).first&.id }
          command["tag_ids"] = command["tag_ids"]&.filter_map { |name| ::Tag.find_by_title(name)&.id }
          command.compact!
        end
      end
    end

    def assignee_from(string)
      string_without_at = string.delete_prefix("@")
      User.all.find { |user| user.mentionable_handles.include?(string_without_at) }
    end

    def build_chat_response_with(generated_commands)
      Command::Result::ChatResponse.new \
        command_lines: response_command_lines_from(generated_commands),
        context_url: response_context_url_from(generated_commands)
    end

    def response_command_lines_from(generated_commands)
      # We translate standalone /search commands as redirections to execute. Otherwise, they
      # will be excluded out from the commands to run, as they represent the context url.
      #
      # TODO: Tidy up this.
      if generated_commands.size == 1 && generated_commands.find { it["command"] == "/search" }
        [ "/visit #{cards_path(**generated_commands.first.without("command"))}" ]
      else
        generated_commands.filter { it["command"] != "/search" }.collect { it["command"] }
      end
    end

    def response_context_url_from(generated_commands)
      if generated_commands.size > 1 && search_command = generated_commands.find { it["command"] == "/search" }
        cards_path(**search_command.without("command"))
      end
    end
end
