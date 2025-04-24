module EventsHelper
  def event_column(event)
    case event.action
    when "card_closed"
      3
    when "card_published"
      1
    else
      2
    end
  end

  def event_cluster_tag(hour, col, &)
    row = 25 - hour
    tag.div class: "event__wrapper", style: "grid-area: #{row}/#{col}", &
  end

  def event_next_page_link(next_day)
    if next_day
      tag.div id: "next_page",
        data: { controller: "fetch-on-visible", fetch_on_visible_url_value: events_days_path(day: next_day.strftime("%Y-%m-%d")) }
    end
  end

  def render_event_grid_cells(columns: 4, rows: 24)
    safe_join((2..rows + 1).map do |row|
      (1..columns).map do |col|
        tag.div class: class_names("event__grid-item"), style: "grid-area: #{row}/#{col};"
      end
    end.flatten)
  end

  def render_column_headers(day_timeline)
    headers = {
      "Added" => day_timeline.events.where(action: "card_published").count,
      "Updated" => nil,
      "Closed" => day_timeline.events.where(action: "card_closed").count
    }

    headers.map do |header, count|
      title = count&.positive? ? "#{header} (#{count})" : header
      content_tag(:h3, title, class: "event__grid-column-title position-sticky")
    end.join.html_safe
  end

  def event_action_sentence(event)
    case event.action
    when "card_assigned"
      if event.assignees.include?(Current.user)
        "#{ event.creator == Current.user ? "You" : event.creator.name } will handle <span style='color: var(--card-color)'>#{ event.eventable.title }</span>".html_safe
      else
        "#{ event.creator == Current.user ? "You" : event.creator.name } assigned #{ event.assignees.pluck(:name).to_sentence } to <span style='color: var(--card-color)'>#{ event.eventable.title }</span>".html_safe
      end
    when "card_unassigned"
      "#{ event.creator == Current.user ? "You" : event.creator.name } unassigned #{ event.assignees.include?(Current.user) ? "yourself" : event.assignees.pluck(:name).to_sentence } from <span style='color: var(--card-color)'>#{ event.eventable.title }</span>".html_safe
    when "card_commented"
      "#{ event.creator == Current.user ? "You" : event.creator.name } commented on <span style='color: var(--card-color)'>#{ event.eventable.title }</span>".html_safe
    when "card_published"
      "#{ event.creator == Current.user ? "You" : event.creator.name } added <span style='color: var(--card-color)'>#{ event.eventable.title }</span>".html_safe
    when "card_closed"
      "#{ event.creator == Current.user ? "You" : event.creator.name } closed <span style='color: var(--card-color)'>#{ event.eventable.title }</span>".html_safe
    when "card_staged"
      "#{event.creator == Current.user ? "You" : event.creator.name} moved <span style='color: var(--card-color)'>#{ event.eventable.title }</span> to the #{event.stage_name} stage".html_safe
    when "card_unstaged"
      "#{event.creator == Current.user ? "You" : event.creator.name} moved <span style='color: var(--card-color)'>#{ event.eventable.title }</span> out ofthe #{event.stage_name} stage".html_safe
    when "card_due_date_added"
      "#{event.creator == Current.user ? "You" : event.creator.name} set the date to #{event.particulars.dig('particulars', 'due_date').to_date.strftime('%B %-d')} on <span style='color: var(--card-color)'>#{ event.eventable.title }</span>".html_safe
    when "card_due_date_changed"
      "#{event.creator == Current.user ? "You" : event.creator.name} changed the date to #{event.particulars.dig('particulars', 'due_date').to_date.strftime('%B %-d')} on <span style='color: var(--card-color)'>#{ event.eventable.title }</span>".html_safe
    when "card_due_date_removed"
      "#{event.creator == Current.user ? "You" : event.creator.name} removed the date on <span style='color: var(--card-color)'>#{ event.eventable.title }</span>"
    when "card_title_changed"
      "#{event.creator == Current.user ? "You" : event.creator.name} renamed <span style='color: var(--card-color)'>#{ event.eventable.title }</span> (was: '#{event.particulars.dig('particulars', 'old_title')})'".html_safe
    end
  end

  def event_action_icon(event)
    case event.action
    when "card_assigned"
      "card_assigned"
    when "card_staged"
      "bolt"
    when "card_unstaged"
      "bolt"
    when "card_commented"
      "comment"
    when "card_title_changed"
      "rename"
    else
      "person"
    end
  end
end
